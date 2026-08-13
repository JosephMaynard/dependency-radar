import {
  AggregatedData,
  DependencyRecord,
  ExecutionHook,
  ExecutionSignal,
  OutdatedResult,
  OutdatedStatus,
  PackagingSignal,
  PackageManager,
  ProjectDependencyPolicy,
  ProjectDependencyPolicySummary,
  Severity,
  ToolResult,
  VulnerabilityAdvisory,
  VulnerabilitySummary,
  WorkspacePackage
} from './types';
import {
  readPackageJson,
  readLicenseFromPackageJson,
  readLicenseFromPackageDir,
  runCommand,
  vulnRiskLevel,
  getDependencyRadarVersion,
  resolvePackageJsonPath
} from './utils';
import {
  inferLicenseFromText,
  pickLicenseRisk,
  validateSpdxExpression
} from './license';
import { buildDependencyFindings } from './findings';
import { isNodeEngineTargetCompatible } from './nodeEngine';
import { applyUpgradeRisk } from './upgradeRisk';
import { MODULE_REPLACEMENTS } from './generated/replacements';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';

interface AggregateInput {
  projectPath: string;
  auditResult?: ToolResult<any>;
  npmLsResult?: ToolResult<any>;
  importGraphResult?: ToolResult<any>;
  outdatedResult?: OutdatedResult;
  supplyChainResult?: ToolResult<any>;
  // Optional: allow CLI to pass a merged view of workspace package.json dependencies
  pkgOverride?: any;
  // Root package.json of the scanned project (used for project metadata output).
  projectPackageJson?: any;
  // Optional policy data discovered outside package.json (e.g. pnpm-workspace.yaml).
  projectDependencyPolicy?: {
    overrides?: Record<string, unknown>;
    resolutions?: Record<string, unknown>;
    sources?: string[];
  };
  // Map dependency name -> workspace package names where it is used/declared
  workspaceUsage?: Map<string, string[]>;
  // Paths to resolve dependency package.json from (workspace package roots, etc.)
  resolvePaths?: string[];
  workspaceEnabled: boolean;
  workspaceType?: PackageManager | 'none';
  workspacePackageCount?: number;
  workspacePackages?: WorkspacePackage[];
  workspacePackageNames?: Set<string>;
  workspacePackageIds?: Set<string>;
  workspacePackagePaths?: Set<string>;
  workspaceLocalDependencyNames?: Set<string>;
  packageManager?: PackageManager;
  packageManagerVersion?: string;
  packageManagerField?: string;
  platform?: string;
  arch?: string;
  ci?: boolean;
  toolVersions?: {
    npm?: string;
    pnpm?: string;
    yarn?: string;
    bun?: string;
  };
  targetNodeMajor?: number;
}

interface NodeInfo {
  name: string;
  version: string;
  key: string;
  depth: number;
  parents: Set<string>;
  children: Set<string>;
  childByName: Map<string, string>;
  dev?: boolean;
  path?: string;
  // True when this exact version appeared as a top-level child of an importer
  // (the project root, or a workspace package in combined workspace graphs).
  importerChild: boolean;
  // importerChild AND the name is declared in the (merged) root manifest.
  // The manifest gate matters for flat tree producers (legacy npm lockfile v1,
  // `yarn list` fallback) where top-level entries include hoisted transitives.
  isDirect: boolean;
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

function findRootCauses(node: NodeInfo, nodeMap: Map<string, NodeInfo>): RootPackageRef[] {
  // If it's a direct dependency, it's its own root cause
  if (node.isDirect) {
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

    if (parent.isDirect) {
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

function asTrimmedString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function normalizeStringList(value: unknown): string[] | undefined {
  if (typeof value === 'string') {
    const single = value.trim();
    return single ? [single] : undefined;
  }
  if (!Array.isArray(value)) return undefined;
  const items = value
    .map((entry) => (typeof entry === 'string' ? entry.trim() : ''))
    .filter(Boolean);
  if (items.length === 0) return undefined;
  return Array.from(new Set(items));
}

function toObjectRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function hasKeys(value: Record<string, unknown> | undefined): value is Record<string, unknown> {
  return Boolean(value && Object.keys(value).length > 0);
}

function mergeRecordObjects(
  ...sources: Array<Record<string, unknown> | undefined>
): Record<string, unknown> | undefined {
  const merged: Record<string, unknown> = {};
  for (const source of sources) {
    if (!source) continue;
    for (const [key, val] of Object.entries(source)) {
      merged[key] = val;
    }
  }
  return Object.keys(merged).length > 0 ? merged : undefined;
}

function normalizeRepository(repository: unknown): string | undefined {
  const direct = asTrimmedString(repository);
  if (direct) return direct;
  const asObject = toObjectRecord(repository);
  if (!asObject) return undefined;
  const url = asTrimmedString(asObject.url);
  if (url) return url;
  const type = asTrimmedString(asObject.type);
  const directory = asTrimmedString(asObject.directory);
  if (type && directory) return `${type} (${directory})`;
  return type;
}

function extractPackageNameFromSelector(selector: string): string | undefined {
  let token = selector.trim();
  if (!token) return undefined;
  if (token.includes('>')) {
    const parts = token.split('>').map((part) => part.trim()).filter(Boolean);
    if (parts.length > 0) token = parts[parts.length - 1];
  }
  if (token.startsWith('npm:')) {
    token = token.slice(4).trim();
  }
  if (!token) return undefined;
  if (token.startsWith('@')) {
    const scopedMatch = token.match(/^@[^/\s]+\/[^@\s]+/);
    return scopedMatch ? scopedMatch[0] : undefined;
  }
  const atIndex = token.indexOf('@');
  const unversioned = atIndex > 0 ? token.slice(0, atIndex) : token;
  const match = unversioned.match(/^[^@\s]+/);
  return match ? match[0] : undefined;
}

function collectPolicyPackageNames(
  entries: Record<string, unknown> | undefined
): string[] | undefined {
  if (!entries) return undefined;
  const names = new Set<string>();
  for (const selector of Object.keys(entries)) {
    const pkgName = extractPackageNameFromSelector(selector);
    if (pkgName) names.add(pkgName);
  }
  if (names.size === 0) return undefined;
  return Array.from(names).sort();
}

function buildProjectDependencyPolicy(
  projectPkg: any,
  inputPolicy?: {
    overrides?: Record<string, unknown>;
    resolutions?: Record<string, unknown>;
    sources?: string[];
  }
): { policy?: ProjectDependencyPolicy; sources?: string[] } {
  const projectPkgOverrides = toObjectRecord(projectPkg?.overrides);
  const projectPkgPnpm = toObjectRecord(projectPkg?.pnpm);
  const projectPkgPnpmOverrides = toObjectRecord(projectPkgPnpm?.overrides);
  const projectPkgResolutions = toObjectRecord(projectPkg?.resolutions);

  const overrides = mergeRecordObjects(
    projectPkgOverrides,
    projectPkgPnpmOverrides,
    inputPolicy?.overrides
  );
  const resolutions = mergeRecordObjects(
    projectPkgResolutions,
    inputPolicy?.resolutions
  );

  const sources = new Set<string>();
  if (hasKeys(projectPkgOverrides)) sources.add('package.json#overrides');
  if (hasKeys(projectPkgPnpmOverrides)) sources.add('package.json#pnpm.overrides');
  if (hasKeys(projectPkgResolutions)) sources.add('package.json#resolutions');
  inputPolicy?.sources?.forEach((source) => {
    const normalized = source.trim();
    if (normalized) sources.add(normalized);
  });

  const policy: ProjectDependencyPolicy = {
    ...(overrides ? { overrides } : {}),
    ...(resolutions ? { resolutions } : {})
  };

  return {
    ...(hasKeys(policy.overrides) || hasKeys(policy.resolutions) ? { policy } : {}),
    ...(sources.size > 0 ? { sources: Array.from(sources).sort() } : {})
  };
}

function buildProjectDependencyPolicySummary(
  policy: ProjectDependencyPolicy | undefined,
  sources?: string[]
): ProjectDependencyPolicySummary | undefined {
  const overrideCount = policy?.overrides ? Object.keys(policy.overrides).length : 0;
  const resolutionCount = policy?.resolutions ? Object.keys(policy.resolutions).length : 0;
  if (overrideCount === 0 && resolutionCount === 0) return undefined;
  const overriddenPackageNames = collectPolicyPackageNames(policy?.overrides);
  const resolvedPackageNames = collectPolicyPackageNames(policy?.resolutions);

  return {
    hasOverrides: overrideCount > 0,
    overrideCount,
    ...(overriddenPackageNames ? { overriddenPackageNames } : {}),
    hasResolutions: resolutionCount > 0,
    resolutionCount,
    ...(resolvedPackageNames ? { resolvedPackageNames } : {}),
    ...(sources && sources.length > 0 ? { sources } : {})
  };
}

function buildProjectMetadata(
  projectPath: string,
  projectPkg: any,
  inputPolicy?: {
    overrides?: Record<string, unknown>;
    resolutions?: Record<string, unknown>;
    sources?: string[];
  }
): AggregatedData['project'] {
  const { policy, sources } = buildProjectDependencyPolicy(projectPkg, inputPolicy);
  const policySummary = buildProjectDependencyPolicySummary(policy, sources);
  const constraints = {
    ...(normalizeStringList(projectPkg?.os) ? { os: normalizeStringList(projectPkg?.os) } : {}),
    ...(normalizeStringList(projectPkg?.cpu) ? { cpu: normalizeStringList(projectPkg?.cpu) } : {}),
    ...(asTrimmedString(projectPkg?.engines?.node) ? { enginesNode: asTrimmedString(projectPkg?.engines?.node) } : {})
  };
  const hasConstraints = Object.keys(constraints).length > 0;

  return {
    projectDir: formatProjectDir(projectPath),
    ...(asTrimmedString(projectPkg?.name) ? { name: asTrimmedString(projectPkg?.name) } : {}),
    ...(asTrimmedString(projectPkg?.version) ? { version: asTrimmedString(projectPkg?.version) } : {}),
    ...(asTrimmedString(projectPkg?.description) ? { description: asTrimmedString(projectPkg?.description) } : {}),
    ...(asTrimmedString(projectPkg?.license) ? { license: asTrimmedString(projectPkg?.license) } : {}),
    ...(normalizeStringList(projectPkg?.keywords) ? { keywords: normalizeStringList(projectPkg?.keywords) } : {}),
    ...(asTrimmedString(projectPkg?.homepage) ? { homepage: asTrimmedString(projectPkg?.homepage) } : {}),
    ...(normalizeRepository(projectPkg?.repository) ? { repository: normalizeRepository(projectPkg?.repository) } : {}),
    ...(hasConstraints ? { constraints } : {}),
    ...(policy ? { dependencyPolicy: policy } : {}),
    ...(policySummary ? { dependencyPolicySummary: policySummary } : {})
  };
}

function getRiskRank(risk: 'green' | 'amber' | 'red'): number {
  if (risk === 'red') return 2;
  if (risk === 'amber') return 1;
  return 0;
}

function maxRisk(
  ...risks: Array<'green' | 'amber' | 'red'>
): 'green' | 'amber' | 'red' {
  let highest: 'green' | 'amber' | 'red' = 'green';
  for (const risk of risks) {
    if (getRiskRank(risk) > getRiskRank(highest)) highest = risk;
  }
  return highest;
}

function resolveLicenseRisk(
  licenseInfo: LicenseBuildResult
): 'green' | 'amber' | 'red' {
  const declaredOrPrimaryRisk = pickLicenseRisk(licenseInfo.licenseIds);
  if (licenseInfo.record.status !== 'mismatch') return declaredOrPrimaryRisk;

  const inferredRisk = licenseInfo.record.inferred
    ? pickLicenseRisk([licenseInfo.record.inferred.spdxId])
    : 'green';
  return maxRisk(declaredOrPrimaryRisk, inferredRisk, 'amber');
}

function isWorkspaceLocalVersion(version: string): boolean {
  const normalized = version.trim().toLowerCase();
  return normalized.startsWith('workspace:') || normalized.startsWith('link:') || normalized.startsWith('file:');
}

/**
 * True when the node's name matches a workspace package whose real version(s)
 * are known and NONE of them equal the node's version — i.e. this node is a
 * same-name EXTERNAL package that must keep aggregating. False when versions
 * match, are unknown, or the name isn't a workspace package.
 */
function isVersionMismatchedNamesake(node: NodeInfo, input: AggregateInput): boolean {
  if (!node.version || !input.workspacePackageIds || input.workspacePackageIds.size === 0) {
    return false;
  }
  let sawRealVersion = false;
  for (const id of input.workspacePackageIds) {
    const at = id.lastIndexOf('@');
    if (at <= 0 || id.slice(0, at) !== node.name) continue;
    const workspaceVersion = id.slice(at + 1);
    if (workspaceVersion === 'workspace') {
      // Placeholder for a versionless workspace manifest — stay permissive.
      return false;
    }
    sawRealVersion = true;
    if (workspaceVersion === node.version) return false;
  }
  return sawRealVersion;
}

function isWorkspacePackageNode(node: NodeInfo, input: AggregateInput): boolean {
  if (!input.workspaceEnabled) return false;
  if (input.workspacePackageIds?.has(node.key)) return true;
  if (isWorkspaceLocalVersion(node.version)) return true;
  // The version-mismatch veto must run before every name-keyed check below:
  // localDependencyNames collapses per-(name,spec) decisions to bare names,
  // so a workspace foo@1 with any local dependent would otherwise swallow an
  // external foo@2 at every depth.
  if (isVersionMismatchedNamesake(node, input)) return false;
  if (input.workspaceLocalDependencyNames?.has(node.name)) return true;

  if (node.path && input.workspacePackagePaths && input.workspacePackagePaths.size > 0) {
    // Exact package-directory equality only: the workspace ROOT is one of
    // these paths, so descendant containment would classify every installed
    // dependency under the repository (node_modules included) as a
    // workspace package and empty the whole report.
    if (input.workspacePackagePaths.has(path.resolve(node.path))) return true;
  }

  if (input.workspacePackageNames?.has(node.name) && node.depth <= 1) {
    return true;
  }

  return false;
}

/**
 * Builds a consolidated AggregatedData object for a dependency and audit scan.
 *
 * Combines package metadata, dependency graph structure, vulnerability summaries,
 * import/usage data, outdated status, supply-chain signals, and per-dependency
 * heuristics (license, execution/installation scripts, packaging, types support,
 * links, peer requirements, and upgrade blockers) into a single summary object.
 *
 * @param input - All inputs and options required to perform aggregation (tool outputs, workspace/configuration, resolution paths, platform/runtime metadata, and optional policy overrides).
 * @returns The assembled AggregatedData containing project metadata, environment info, per-dependency records, findings, and summary counts.
 */
export async function aggregateData(input: AggregateInput): Promise<AggregatedData> {
  const pkg = input.pkgOverride || (await readPackageJson(input.projectPath));
  let projectPkg = input.projectPackageJson;
  if (!projectPkg) {
    try {
      projectPkg = await readPackageJson(input.projectPath);
    } catch {
      projectPkg = {};
    }
  }
  const project = buildProjectMetadata(
    input.projectPath,
    projectPkg,
    input.projectDependencyPolicy
  );

  // Get git branch
  const gitBranch = await getGitBranch(input.projectPath);

  const nodeMap = buildNodeMap(input.npmLsResult?.data, Boolean(input.workspaceEnabled));
  for (const node of nodeMap.values()) {
    node.isDirect = node.importerChild && isDirectDependency(node.name, pkg);
  }
  const vulnerabilityIndex = parseVulnerabilities(input.auditResult?.data);
  const importGraph = normalizeImportGraph(input.importGraphResult?.data);
  const usageResult = buildUsageSummary(importGraph, input.projectPath);
  const outdatedById = buildOutdatedMap(input.outdatedResult);
  const supplyChain = normalizeSupplyChain(input.supplyChainResult?.data);
  const outdatedUnknownNames = new Set(input.outdatedResult?.unknownNames || []);
  const packageMetaCache = new Map<string, PackageMeta>();
  const resolvePaths = input.resolvePaths && input.resolvePaths.length > 0
    ? input.resolvePaths
    : [input.projectPath];
  const packageStatCache = new Map<string, PackageStats>();

  const dependencies: Record<string, DependencyRecord> = {};
  const licenseCache = new Map<string, { license?: string; licenseText?: string }>();
  const nodeEngineRanges: string[] = [];

  const nodes = Array.from(nodeMap.values()).filter(
    (node) => !isWorkspacePackageNode(node, input)
  );
  let directCount = 0;
  const MAX_TOP_ROOT_PACKAGES = 10; // cap to keep payload size predictable
  const MAX_TOP_PARENT_PACKAGES = 5; // cap for direct parents to keep payload size predictable

  // Import evidence resolves specifiers to a package NAME; when several
  // versions of that name are installed, the importing file actually gets
  // the nearest (hoisted) one. Deeper duplicates never win resolution, so a
  // vulnerable nested copy must not inherit the evidence and trip
  // directly-imported-vuln. When several versions tie at the shallowest
  // depth (different workspaces declaring different majors), evidence is
  // split per importing file by workspace ownership where possible.
  const nodesByName = new Map<string, NodeInfo[]>();
  for (const node of nodes) {
    const list = nodesByName.get(node.name) || [];
    list.push(node);
    nodesByName.set(node.name, list);
  }

  const workspaceRelByPath = new Map<string, string>();
  if (input.workspacePackagePaths) {
    for (const wsPath of input.workspacePackagePaths) {
      workspaceRelByPath.set(
        wsPath,
        path.relative(input.projectPath, wsPath).split(path.sep).join('/'),
      );
    }
  }

  const fileOwnerWorkspace = (file: string): string | undefined => {
    let best: string | undefined;
    let bestLen = -1;
    for (const [wsPath, rel] of workspaceRelByPath) {
      if (rel === '' || rel === '.') {
        if (bestLen < 0) {
          best = wsPath;
          bestLen = 0;
        }
        continue;
      }
      if ((file === rel || file.startsWith(`${rel}/`)) && rel.length > bestLen) {
        best = wsPath;
        bestLen = rel.length;
      }
    }
    return best;
  };

  const nodeWorkspaceOwners = (node: NodeInfo): Set<string> => {
    const owners = new Set<string>();
    for (const parentKey of node.parents) {
      const parent = nodeMap.get(parentKey);
      if (!parent?.path) continue;
      const resolved = path.resolve(parent.path);
      if (input.workspacePackagePaths?.has(resolved)) owners.add(resolved);
    }
    if (node.importerChild && workspaceRelByPath.size > 0) {
      const rootPath = path.resolve(input.projectPath);
      if (input.workspacePackagePaths?.has(rootPath)) owners.add(rootPath);
    }
    return owners;
  };

  const attributeImportUsage = (
    node: NodeInfo,
    usage: UsageSummary | undefined,
  ): UsageSummary | undefined => {
    if (!usage) return undefined;
    const siblings = nodesByName.get(node.name) || [];
    if (siblings.length <= 1) return usage;
    const minDepth = Math.min(...siblings.map((sibling) => sibling.depth));
    // Deeper duplicates lose to the hoisted copy outright.
    if (node.depth > minDepth) return undefined;
    const tied = siblings.filter((sibling) => sibling.depth === minDepth);
    if (tied.length <= 1) return usage;
    // Equal-depth versions (multi-workspace): split evidence per importing
    // file by workspace ownership. If ownership can't be established for
    // every tied version, stay permissive and attribute to all of them.
    const ownersByNode = tied.map((sibling) => nodeWorkspaceOwners(sibling));
    if (ownersByNode.some((owners) => owners.size === 0)) return usage;
    const myOwners = nodeWorkspaceOwners(node);
    const ownedFiles = usage.topFiles.filter((file) => {
      const owner = fileOwnerWorkspace(file);
      return owner !== undefined && myOwners.has(owner);
    });
    if (ownedFiles.length === 0) return undefined;
    return { fileCount: ownedFiles.length, topFiles: ownedFiles };
  };

  for (const node of nodes) {
    const direct = node.isDirect;
    if (direct) directCount += 1;
    const cacheKey = `${node.name}@${node.version}`;
    const cachedLicense = licenseCache.get(cacheKey);
    const licenseSource = cachedLicense ||
      (node.path
        ? (await readLicenseFromPackageDir(node.path))
        : (await readLicenseFromPackageJson(node.name, resolvePaths, node.version))) ||
      { license: undefined };
    if (!licenseCache.has(cacheKey)) {
      licenseCache.set(cacheKey, licenseSource);
    }
    const vulnerabilities = vulnerabilitiesForNode(vulnerabilityIndex, node);

    const licenseInfo = buildLicenseInfo(licenseSource.license, licenseSource.licenseText);
    const licenseRisk = resolveLicenseRisk(licenseInfo);
    
    // Calculate root causes (direct dependencies that cause this to be installed)
    const rootCauses = findRootCauses(node, nodeMap);

    const packageInsights = await gatherPackageInsights(
      node.name,
      node.version,
      resolvePaths,
      packageMetaCache,
      packageStatCache
    );
    if (packageInsights.nodeEngine) {
      nodeEngineRanges.push(packageInsights.nodeEngine);
    }

    const scope = determineScope(node.name, direct, rootCauses, pkg);
    const importUsage = attributeImportUsage(
      node,
      usageResult.summary.get(node.name),
    );
    const runtimeImpact = usageResult.runtimeImpact.get(node.name);
    const introduction = determineIntroduction(direct, scope, rootCauses, runtimeImpact);
    const parentIds = Array.from(node.parents).sort();
    const origins = buildOrigins(
      rootCauses,
      parentIds,
      input.workspaceUsage?.get(node.name),
      input.workspaceEnabled,
      MAX_TOP_ROOT_PACKAGES,
      MAX_TOP_PARENT_PACKAGES
    );
    const execution = packageInsights.execution;
    const packaging = packageInsights.packaging;
    const id = node.key;
    const upgrade = buildUpgradeBlock(packageInsights);
    const outdated = resolveOutdated(node, direct, outdatedById, outdatedUnknownNames);
    const subDeps = buildSubDeps(packageInsights.declaredDependencies, node);

    // Group fields by reviewer question to keep the JSON readable and source-agnostic.
    // Optional fields are only attached when meaningful to keep the payload sparse.
    const upgradeRecord: DependencyRecord['upgrade'] = {
      nodeEngine: packageInsights.nodeEngine,
      ...(outdated ? { outdatedStatus: outdated.status } : {}),
      ...(outdated?.latestVersion ? { latestVersion: outdated.latestVersion } : {}),
      ...(upgrade?.blockers ? { blockers: upgrade.blockers } : {}),
      ...(upgrade?.blocksNodeMajor ? { blocksNodeMajor: upgrade.blocksNodeMajor } : {}),
      ...(typeof input.targetNodeMajor === 'number' && packageInsights.nodeEngine
        ? { targetNodeCompatible: isNodeEngineTargetCompatible(packageInsights.nodeEngine, input.targetNodeMajor) }
        : {})
    };

    dependencies[id] = {
      package: {
        id,
        name: node.name,
        version: node.version,
        ...(packageInsights.description ? { description: packageInsights.description } : {}),
        ...(typeof packageInsights.fileCount === 'number' ? { fileCount: packageInsights.fileCount } : {}),
        ...(packageInsights.hasBin ? { hasBin: true } : {}),
        deprecated: packageInsights.deprecated,
        links: {
          npm: `https://www.npmjs.com/package/${node.name}`,
          ...(packageInsights.links?.repository ? { repository: packageInsights.links.repository } : {}),
          ...(packageInsights.links?.homepage ? { homepage: packageInsights.links.homepage } : {}),
          ...(packageInsights.links?.bugs ? { bugs: packageInsights.links.bugs } : {})
        }
      },
      compliance: {
        license: licenseInfo.record,
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
        ...(subDeps ? { subDeps } : {})
      },
      ...(execution ? { execution } : {}),
      ...(packaging ? { packaging } : {})
    };

    // Offline lookup against the vendored e18e module-replacements catalogue.
    const replacementEntry = MODULE_REPLACEMENTS[node.name];
    if (replacementEntry) {
      dependencies[id].replacement = {
        source: 'e18e-module-replacements',
        manifest: replacementEntry.manifest,
        type: replacementEntry.type,
        replacements: replacementEntry.replacements,
        ...(replacementEntry.docUrl ? { docUrl: replacementEntry.docUrl } : {})
      };
    }
  }

  const minRequiredMajor = deriveMinRequiredMajor(nodeEngineRanges);
  const runtimeVersion = process.version;
  const nodeVersion = process.versions.node;
  const dependencyCount = nodes.length;
  const transitiveCount = dependencyCount - directCount;

  const aggregated: AggregatedData = {
    schemaVersion: '1.7',
    generatedAt: new Date().toISOString(),
    dependencyRadarVersion,
    git: {
      branch: gitBranch || ''
    },
    project,
    environment: {
      nodeVersion,
      runtimeVersion,
      minRequiredMajor: minRequiredMajor ?? 0,
      ...(typeof input.targetNodeMajor === 'number' ? { targetNodeMajor: input.targetNodeMajor } : {}),
      ...(input.platform ? { platform: input.platform } : {}),
      ...(input.arch ? { arch: input.arch } : {}),
      ...(typeof input.ci === 'boolean' ? { ci: input.ci } : {}),
      ...(input.packageManagerField ? { packageManagerField: input.packageManagerField } : {}),
      ...(input.packageManager ? { packageManager: input.packageManager } : {}),
      ...(input.packageManagerVersion ? { packageManagerVersion: input.packageManagerVersion } : {}),
      ...(input.toolVersions ? { toolVersions: input.toolVersions } : {})
    },
    workspaces: {
      enabled: input.workspaceEnabled,
      ...(input.workspaceType ? { type: input.workspaceType } : {}),
      ...(typeof input.workspacePackageCount === 'number'
        ? { packageCount: input.workspacePackageCount }
        : {}),
      ...(input.workspacePackages ? { workspacePackages: input.workspacePackages } : {})
    },
    summary: {
      dependencyCount,
      directCount,
      transitiveCount
    },
    ...(supplyChain ? { supplyChain } : {}),
    dependencies
  };
  applyUpgradeRisk(aggregated);
  const findings = buildDependencyFindings(aggregated, { targetNodeMajor: input.targetNodeMajor });
  aggregated.findings = findings;
  aggregated.summary.findingCount = findings.length;
  return aggregated;
}

function normalizeSupplyChain(data: any): AggregatedData['supplyChain'] | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const signals = Array.isArray(data.signals) ? data.signals : [];
  const signatureAudit = data.signatureAudit && typeof data.signatureAudit === 'object'
    ? data.signatureAudit
    : undefined;
  if (signals.length === 0 && !signatureAudit) return undefined;
  return {
    signals,
    ...(signatureAudit ? { signatureAudit } : {})
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

function buildNodeMap(lsData: any, workspaceMode = false): Map<string, NodeInfo> {
  const map = new Map<string, NodeInfo>();
  // In combined workspace graphs each workspace package is a synthetic depth-1
  // node, so the importer's real direct dependencies sit at traversal depth 2.
  const importerDepth = workspaceMode ? 2 : 1;

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
        childByName: new Map<string, string>(),
        dev: node.dev,
        path: typeof node.path === 'string' ? node.path : undefined,
        importerChild: depth === importerDepth,
        isDirect: false
      });
    } else {
      const existing = map.get(key)!;
      existing.depth = Math.min(existing.depth, depth);
      if (depth === importerDepth) existing.importerChild = true;
      if (parentKey) existing.parents.add(parentKey);
      if (existing.dev === undefined && node.dev !== undefined) existing.dev = node.dev;
      if (!existing.path && typeof node.path === 'string') existing.path = node.path;
      if (!existing.children) existing.children = new Set<string>();
      if (!existing.childByName) existing.childByName = new Map<string, string>();
    }
    if (node.dependencies && typeof node.dependencies === 'object') {
      Object.entries<any>(node.dependencies).forEach(([depName, child]: [string, any]) => {
        const childVersion = child?.version || 'unknown';
        const childKey = `${depName}@${childVersion}`;
        const current = map.get(key);
        if (current) {
          current.children.add(childKey);
          current.childByName.set(depName, childKey);
        }
        traverse(child, depth + 1, key, depName);
      });
    }
  };

  if (lsData && lsData.dependencies) {
    Object.entries<any>(lsData.dependencies).forEach(([depName, child]: [string, any]) => traverse(child, 1, undefined, depName));
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

type VulnerabilityIndex = {
  byName: Map<string, VulnerabilitySummary>;
  byNodePath: Map<string, VulnerabilitySummary>;
  byPackageId: Map<string, VulnerabilitySummary>;
  namesWithNodePaths: Set<string>;
  namesWithPackageIds: Set<string>;
};

function summarizeAdvisories(advisories: VulnerabilityAdvisory[]): VulnerabilitySummary {
  const sorted = [...advisories].sort((a, b) => {
    const order = { critical: 4, high: 3, moderate: 2, low: 1 };
    const diff = order[b.severity] - order[a.severity];
    if (diff !== 0) return diff;
    return a.title.localeCompare(b.title);
  });
  const counts = { low: 0, moderate: 0, high: 0, critical: 0 };
  for (const advisory of sorted) counts[advisory.severity] += 1;
  return {
    counts,
    highestSeverity: computeHighestSeverity(counts),
    risk: vulnRiskLevel(counts),
    ...(sorted.length > 0 ? { advisories: sorted } : {})
  };
}

function vulnerabilitiesForNode(index: VulnerabilityIndex, node: NodeInfo): VulnerabilitySummary {
  if (node.path) {
    const pathMatch = index.byNodePath.get(path.resolve(node.path));
    if (pathMatch) return pathMatch;
    if (index.namesWithNodePaths.has(node.name)) return emptyVulnSummary();
  }
  const packageIdMatch = index.byPackageId.get(node.key);
  if (packageIdMatch) return packageIdMatch;
  if (index.namesWithPackageIds.has(node.name)) return emptyVulnSummary();
  return index.byName.get(node.name) || emptyVulnSummary();
}

function parseVulnerabilities(auditData: any): VulnerabilityIndex {
  const map = new Map<string, VulnerabilitySummary>();
  const nodePathsByName = new Map<string, Set<string>>();
  const advisoriesByAuditKey = new Map<string, VulnerabilityAdvisory[]>();
  const advisoriesByNodePath = new Map<string, VulnerabilityAdvisory[]>();
  const advisoriesByPackageId = new Map<string, VulnerabilityAdvisory[]>();
  if (!auditData) {
    return {
      byName: map,
      byNodePath: new Map(),
      byPackageId: new Map(),
      namesWithNodePaths: new Set(),
      namesWithPackageIds: new Set(),
    };
  }

  const ensureEntry = (name: string) => {
    if (!map.has(name)) {
      map.set(name, emptyVulnSummary());
    }
    return map.get(name)!;
  };

  const advisoryKeys = new Map<string, Set<string>>();
  const deferredViaStrings: Array<{
    auditKey: string;
    name: string;
    nodePaths: string[];
    via: string[];
  }> = [];
  const addAdvisoryToList = (
    target: Map<string, VulnerabilityAdvisory[]>,
    key: string,
    advisory: VulnerabilityAdvisory,
  ) => {
    const advisories = target.get(key) || [];
    if (!advisories.some((entry) => entry.id === advisory.id && entry.vulnerableRange === advisory.vulnerableRange)) {
      advisories.push(advisory);
    }
    target.set(key, advisories);
  };
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
    Object.entries<any>(auditData.vulnerabilities).forEach(([auditKey, item]) => {
      const name = item.name || 'unknown';
      const nodePaths = Array.isArray(item.nodes)
        ? item.nodes
          .filter((node: unknown): node is string => typeof node === 'string' && node.trim().length > 0)
          .map((node: string) => path.resolve(node))
        : [];
      if (nodePaths.length > 0) {
        const paths = nodePathsByName.get(name) || new Set<string>();
        for (const nodePath of nodePaths) paths.add(nodePath);
        nodePathsByName.set(name, paths);
      }
      const viaList = Array.isArray(item.via) ? item.via : [];
      const itemAdvisories: VulnerabilityAdvisory[] = [];
      let added = false;
      for (const via of viaList) {
        if (via && typeof via === 'object') {
          const advisory = buildAdvisoryFromVia(via, item);
          if (advisory) {
            addAdvisory(name, advisory);
            itemAdvisories.push(advisory);
            added = true;
          }
        }
      }
      const viaStrings = viaList.filter((via: unknown) => typeof via === 'string') as string[];
      if (viaStrings.length > 0) {
        deferredViaStrings.push({ auditKey, name, nodePaths, via: viaStrings });
      }
      if (!added) {
        const fallback = buildAdvisoryFromVia(item, item);
        if (fallback) {
          addAdvisory(name, fallback);
          itemAdvisories.push(fallback);
        }
      }
      for (const advisory of itemAdvisories) {
        addAdvisoryToList(advisoriesByAuditKey, auditKey, advisory);
        for (const nodePath of nodePaths) {
          addAdvisoryToList(advisoriesByNodePath, nodePath, advisory);
        }
      }
    });
  }

  if (auditData.advisories) {
    Object.values<any>(auditData.advisories).forEach((adv: any) => {
      const name = adv.module_name || adv.module || 'unknown';
      const advisory = buildAdvisoryFromLegacy(adv);
      if (advisory) {
        addAdvisory(name, advisory);
        const findings = Array.isArray(adv.findings) ? adv.findings : [];
        for (const finding of findings) {
          const version = typeof finding?.version === 'string' ? finding.version.trim() : '';
          if (!version) continue;
          const packageId = `${name}@${version}`;
          const advisories = advisoriesByPackageId.get(packageId) || [];
          if (!advisories.some((entry) => entry.id === advisory.id && entry.vulnerableRange === advisory.vulnerableRange)) {
            advisories.push(advisory);
          }
          advisoriesByPackageId.set(packageId, advisories);
        }
      }
    });
  }

  // One-level expansion: map string "via" references to their advisories while preserving paths.
  for (const entry of deferredViaStrings) {
    for (const refName of entry.via) {
      const referenced = advisoriesByAuditKey.get(refName);
      if (referenced) {
        for (const advisory of referenced) {
          addAdvisory(entry.name, advisory);
          addAdvisoryToList(advisoriesByAuditKey, entry.auditKey, advisory);
          for (const nodePath of entry.nodePaths) {
            addAdvisoryToList(advisoriesByNodePath, nodePath, advisory);
          }
        }
      }
    }
  }

  map.forEach((entry, name) => {
    map.set(name, summarizeAdvisories(entry.advisories || []));
  });

  const byNodePath = new Map<string, VulnerabilitySummary>();
  for (const [nodePath, advisories] of advisoriesByNodePath) {
    byNodePath.set(nodePath, summarizeAdvisories(advisories));
  }
  const byPackageId = new Map<string, VulnerabilitySummary>();
  for (const [packageId, advisories] of advisoriesByPackageId) {
    byPackageId.set(packageId, summarizeAdvisories(advisories));
  }

  return {
    byName: map,
    byNodePath,
    byPackageId,
    namesWithNodePaths: new Set(nodePathsByName.keys()),
    namesWithPackageIds: new Set(Array.from(advisoriesByPackageId.keys()).map((id) => id.slice(0, id.lastIndexOf('@')))),
  };
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
      category: classifyFileCategory(file)
    }));
    // Rank: prefer non-testing files, then higher import counts, then closer to root.
    entries.sort((a, b) => {
      const aIsTest = a.category === 'testing';
      const bIsTest = b.category === 'testing';
      if (aIsTest !== bIsTest) return aIsTest ? 1 : -1;
      if (b.count !== a.count) return b.count - a.count;
      if (a.depth !== b.depth) return a.depth - b.depth;
      return a.file.localeCompare(b.file);
    });
    summary.set(dep, {
      fileCount: fileMap.size,
      topFiles: entries.slice(0, 5).map((entry) => entry.file)
    });
    runtimeImpact.set(dep, determineRuntimeImpactFromFiles(entries));
  }

  return { summary, runtimeImpact };
}

function isDirectDependency(name: string, pkg: any): boolean {
  return Boolean(
    (pkg.dependencies && pkg.dependencies[name]) ||
    (pkg.devDependencies && pkg.devDependencies[name]) ||
    (pkg.optionalDependencies && pkg.optionalDependencies[name]) ||
    (pkg.peerDependencies && pkg.peerDependencies[name])
  );
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
  // Optional outranks dev: optional deps install and execute in production,
  // so a package reachable via both paths must keep its production scope.
  if (scopes.has('optional')) return 'optional';
  if (scopes.has('dev')) return 'dev';
  if (scopes.has('peer')) return 'peer';
  return 'runtime';
}

function buildSubDeps(
  declared: PackageInsights['declaredDependencies'],
  node: NodeInfo
): NonNullable<DependencyRecord['graph']['subDeps']> | undefined {
  const out: NonNullable<DependencyRecord['graph']['subDeps']> = {};
  const entries: Array<[keyof PackageInsights['declaredDependencies'], keyof NonNullable<DependencyRecord['graph']['subDeps']>]> = [
    ['dep', 'dep'],
    ['dev', 'dev'],
    ['opt', 'opt'],
    ['peer', 'peer']
  ];

  for (const [declaredKey, outKey] of entries) {
    const group = declared[declaredKey];
    const names = Object.keys(group);
    if (names.length === 0) continue;
    const bucket: Record<string, [string, string | null]> = {};
    for (const name of names.sort()) {
      const range = group[name];
      const resolved = node.childByName.get(name) || null;
      bucket[name] = [range, resolved];
    }
    if (Object.keys(bucket).length > 0) {
      out[outKey] = bucket;
    }
  }

  return Object.keys(out).length > 0 ? out : undefined;
}

function buildOrigins(
  rootCauses: RootPackageRef[],
  parentIds: string[],
  workspaceList: string[] | undefined,
  workspaceEnabled: boolean,
  maxTopRoots: number,
  maxTopParents: number
): { rootPackageCount: number; topRootPackages: RootPackageRef[]; parentPackageCount: number; topParentPackages: string[]; workspaces?: string[] } {
  const origins: { rootPackageCount: number; topRootPackages: RootPackageRef[]; parentPackageCount: number; topParentPackages: string[]; workspaces?: string[] } = {
    rootPackageCount: rootCauses.length,
    topRootPackages: rootCauses.slice(0, maxTopRoots),
    parentPackageCount: parentIds.length,
    topParentPackages: parentIds.slice(0, maxTopParents)
  };
  if (workspaceEnabled && workspaceList && workspaceList.length > 0) {
    origins.workspaces = workspaceList;
  }
  return origins;
}

function isTestFile(file: string): boolean {
  return (
    /(^|\/)(__tests__|__mocks__|test|tests|testing|e2e|cypress|playwright|__snapshots__)(\/|$)/.test(file) ||
    /\.(test|spec|e2e)\./.test(file) ||
    /(^|\/)(jest|vitest|playwright|cypress)\.config\./.test(file) ||
    /(^|\/)\.(jest|vitest|playwright|cypress)(rc|\.config)?(\..*)?$/.test(file)
  );
}

function isToolingFile(file: string): boolean {
  return (
    /(^|\/)(eslint|prettier|stylelint|commitlint|lint-staged|husky|renovate|semantic-release|release-it|lefthook|dependabot)[^\/]*\./.test(file) ||
    /(^|\/)\.(eslint|eslintrc|prettier|prettierrc|stylelint|stylelintrc|commitlint|commitlintrc|lint-staged|lintstagedrc|husky|huskyrc|renovate|semantic-release|release-it|lefthook|dependabot)(rc|\.config)?(\..*)?$/.test(file)
  );
}

function isBuildFile(file: string): boolean {
  return (
    /(^|\/)(webpack|rollup|vite|tsconfig|babel|swc|esbuild|parcel|gulpfile|gruntfile|postcss|tailwind|storybook|rspack|turbo|nx|metro)[^\/]*\./.test(file) ||
    /(^|\/)scripts\/(build|bundle|compile|release|deploy)(\/|\.|$)/.test(file) ||
    /(^|\/)\.(webpack|rollup|vite|tsconfig|babel|babelrc|swc|swcrc|esbuild|parcel|postcss|postcssrc|tailwind|storybook|rspack|turbo|nx|metro)(rc|\.config)?(\..*)?$/.test(file)
  );
}

type RuntimeCategory = 'runtime' | 'build' | 'testing' | 'tooling';

function classifyFileCategory(file: string): RuntimeCategory {
  if (isTestFile(file)) return 'testing';
  if (isToolingFile(file)) return 'tooling';
  if (isBuildFile(file)) return 'build';
  return 'runtime';
}

function determineRuntimeImpactFromFiles(
  files: Array<{ file: string; count: number }>
): DependencyRecord['usage']['runtimeImpact'] {
  const weights: Record<RuntimeCategory, number> = {
    runtime: 0,
    build: 0,
    testing: 0,
    tooling: 0
  };
  let total = 0;

  for (const entry of files) {
    const category = classifyFileCategory(entry.file);
    const weight = Number.isFinite(entry.count) && entry.count > 0 ? entry.count : 1;
    weights[category] += weight;
    total += weight;
  }

  if (total <= 0) return 'runtime';

  const ranked = (Object.entries(weights) as Array<[RuntimeCategory, number]>)
    .filter(([, weight]) => weight > 0)
    .sort((a, b) => b[1] - a[1]);
  if (ranked.length === 0) return 'runtime';
  if (ranked.length === 1) return ranked[0][0];

  const [top, second] = ranked;
  const topRatio = top[1] / total;
  const secondRatio = second ? second[1] / total : 0;

  // Strong dominance: classify as a single category instead of defaulting to mixed.
  if (topRatio >= 0.7) return top[0];
  // Runtime is common; tolerate a small amount of non-runtime usage before calling it mixed.
  if (top[0] === 'runtime' && topRatio >= 0.6 && secondRatio <= 0.25) return 'runtime';
  // Testing-heavy dependencies often leak a small runtime footprint (helpers in fixtures).
  if (top[0] === 'testing' && topRatio >= 0.6 && secondRatio <= 0.3) return 'testing';
  return 'mixed';
}

type LicenseBuildResult = {
  record: DependencyRecord['compliance']['license'];
  licenseIds: string[];
};

function buildLicenseInfo(declaredRaw?: string, licenseText?: string): LicenseBuildResult {
  const declaredValue = typeof declaredRaw === 'string' ? declaredRaw.trim() : '';
  const hasDeclared = Boolean(declaredValue);
  const declaredValidation = hasDeclared ? validateSpdxExpression(declaredValue) : undefined;
  const inferred = licenseText ? inferLicenseFromText(licenseText) : undefined;

  const record: DependencyRecord['compliance']['license'] = {
    status: 'unknown'
  };

  if (hasDeclared && declaredValidation) {
    record.declared = {
      spdxId: declaredValidation.normalized || declaredValue,
      expression: declaredValidation.expression,
      deprecated: declaredValidation.deprecated,
      valid: declaredValidation.valid
    };
    if (declaredValidation.exceptions.length === 1) {
      record.exception = declaredValidation.exceptions[0];
    }
  }

  if (inferred) {
    record.inferred = {
      spdxId: inferred.spdxId,
      confidence: inferred.confidence
    };
  }

  if (hasDeclared && declaredValidation && !declaredValidation.valid) {
    record.status = 'invalid-spdx';
  } else if (declaredValidation?.valid && inferred && inferred.confidence !== 'low') {
    record.status = declaredValidation.normalized === inferred.spdxId ? 'match' : 'mismatch';
  } else if (declaredValidation?.valid) {
    record.status = 'declared-only';
  } else if (inferred) {
    record.status = 'inferred-only';
  } else {
    record.status = 'unknown';
  }

  if (declaredValidation?.valid) {
    return { record, licenseIds: declaredValidation.licenseIds };
  }
  if (inferred) {
    return { record, licenseIds: [inferred.spdxId] };
  }
  return { record, licenseIds: [] };
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
  scope: DependencyScope,
  rootCauses: RootPackageRef[],
  runtimeImpact: DependencyRecord['usage']['runtimeImpact'] | undefined
): DependencyRecord['usage']['introduction'] {
  const rootNames = rootCauses.map((root) => root.name);
  if (direct) return 'direct';
  if (runtimeImpact === 'testing') return 'testing';
  if (runtimeImpact === 'tooling' || runtimeImpact === 'build') return 'tooling';
  if (scope === 'dev') return 'tooling';
  if (scope === 'peer' && runtimeImpact !== 'runtime') return 'tooling';
  if (rootNames.length > 0 && rootNames.every((root) => isToolingPackage(root))) return 'tooling';
  if (rootNames.some((root) => isFrameworkPackage(root))) return 'framework';
  if (rootNames.length > 0) return 'transitive';
  return 'unknown';
}

// Upgrade blockers derived only from local metadata (no external lookups).
type UpgradeBlocker =
  | 'nodeEngine'
  | 'peerDependency'
  | 'nativeBindings'
  | 'installScripts'
  | 'deprecated';

function isPermissiveNodeEngineRange(range: string): boolean {
  const compact = range.trim().toLowerCase().replace(/\s+/g, '');
  return compact === '*' || compact === 'x' || compact === '>=0' || compact === '>=0.0' || compact === '>=0.0.0';
}

function hasNodeEngineUpgradeBlocker(nodeEngine: string | null): boolean {
  if (!nodeEngine || !nodeEngine.trim()) return false;
  if (isPermissiveNodeEngineRange(nodeEngine)) return false;

  const clauses = nodeEngine.split('||').map((clause) => clause.trim()).filter(Boolean);
  if (clauses.length > 0 && clauses.every((clause) => isPermissiveNodeEngineRange(clause))) {
    return false;
  }

  const minMajor = parseMinMajorFromRange(nodeEngine);
  if (minMajor !== undefined) {
    if (minMajor > 0) return true;
    return /<\s*\d/.test(nodeEngine);
  }

  if (/<\s*\d/.test(nodeEngine)) return true;

  const majors = Array.from(nodeEngine.matchAll(/v?(\d+)/g))
    .map((match) => Number.parseInt(match[1], 10))
    .filter((major) => Number.isFinite(major));
  return majors.some((major) => major > 0);
}

function hasInstallScriptUpgradeBlocker(execution: DependencyRecord['execution'] | undefined): boolean {
  const hooks = execution?.scripts?.hooks;
  if (!hooks || hooks.length === 0) return false;
  return hooks.includes('preinstall') || hooks.includes('install') || hooks.includes('postinstall');
}

function buildUpgradeBlock(
  insights: PackageInsights
): { blockers: UpgradeBlocker[]; blocksNodeMajor?: true } | undefined {
  const blockers: UpgradeBlocker[] = [];
  const hasNodeEngineBlocker = hasNodeEngineUpgradeBlocker(insights.nodeEngine);
  const hasNativeBindingsBlocker = Boolean(insights.execution?.native);
  const hasInstallScriptBlocker = hasInstallScriptUpgradeBlocker(insights.execution);

  if (hasNodeEngineBlocker) blockers.push('nodeEngine');
  if (insights.requiredPeerDependencies > 0) blockers.push('peerDependency');
  if (hasNativeBindingsBlocker) blockers.push('nativeBindings');
  if (hasInstallScriptBlocker) blockers.push('installScripts');
  if (insights.deprecated) blockers.push('deprecated');

  if (blockers.length === 0) return undefined;
  const blocksNodeMajor = hasNodeEngineBlocker || hasNativeBindingsBlocker || hasInstallScriptBlocker;
  return {
    blockers,
    ...(blocksNodeMajor ? { blocksNodeMajor: true as const } : {})
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
  hasShrinkwrap: boolean;
  fileCount: number;
}

interface PackageInsights {
  deprecated: boolean;
  nodeEngine: string | null;
  requiredPeerDependencies: number;
  description?: string;
  fileCount?: number;
  hasBin: boolean;
  declaredDependencies: {
    dep: Record<string, string>;
    dev: Record<string, string>;
    peer: Record<string, string>;
    opt: Record<string, string>;
  };
  links?: {
    repository?: string;
    homepage?: string;
    bugs?: string;
  };
  execution?: DependencyRecord['execution'];
  packaging?: DependencyRecord['packaging'];
  tsTypes: 'bundled' | 'definitelyTyped' | 'none' | 'unknown';
}

/**
 * Collects package metadata and bounded filesystem heuristics to produce insights used for dependency analysis.
 *
 * Gathers package.json data (description, engines, scripts, bin, dependencies, links), computes file-based stats when the package directory is available, detects TypeScript typing availability (bundled or DefinitelyTyped), counts required peer dependencies, and derives execution and packaging signals for use in aggregation and risk heuristics.
 *
 * @param resolvePaths - Array of filesystem roots to use when resolving package metadata.
 * @param metaCache - Cache mapping package id (`name` or `name@version`) to previously loaded PackageMeta to avoid repeated resolution and parsing.
 * @param statCache - Cache mapping package directory paths to previously computed PackageStats to avoid repeated filesystem scans.
 * @returns A PackageInsights object containing deprecation, engine constraint, required peer count, optional fileCount, declared dependency maps, links, execution signals, optional packaging signals, and TypeScript types information.
 */
async function gatherPackageInsights(
  name: string,
  version: string,
  resolvePaths: string[],
  metaCache: Map<string, PackageMeta>,
  statCache: Map<string, PackageStats>
): Promise<PackageInsights> {
  const meta = await loadPackageMeta(name, resolvePaths, metaCache, version);
  if (!meta) {
    return {
      deprecated: false,
      nodeEngine: null,
      requiredPeerDependencies: 0,
      hasBin: false,
      declaredDependencies: { dep: {}, dev: {}, peer: {}, opt: {} },
      tsTypes: 'unknown'
    };
  }
  const pkg = meta?.pkg || {};
  const dir = meta?.dir;
  const stats = dir ? await calculatePackageStats(dir, statCache) : undefined;
  const peerDependencies = normalizeDeclaredDeps(pkg.peerDependencies);
  const declaredDependencies = {
    dep: normalizeDeclaredDeps(pkg.dependencies),
    dev: normalizeDeclaredDeps(pkg.devDependencies),
    peer: peerDependencies,
    opt: normalizeDeclaredDeps(pkg.optionalDependencies)
  };
  const requiredPeerDependencies = countRequiredPeerDependencies(peerDependencies, pkg.peerDependenciesMeta);

  const scripts = pkg.scripts || {};
  const deprecated = Boolean(pkg.deprecated);
  const nodeEngine = typeof pkg.engines?.node === 'string' ? pkg.engines.node : null;
  const description = typeof pkg.description === 'string' && pkg.description.trim()
    ? pkg.description.trim()
    : undefined;
  const hasBin = hasPackageBin(pkg.bin);

  const hasDefinitelyTyped = await hasDefinitelyTypedPackage(name, resolvePaths, metaCache);
  const tsTypes = determineTypes(pkg, stats?.hasDts || false, hasDefinitelyTyped);
  const links = extractPackageLinks(pkg);
  const execution = await deriveExecutionInfo(pkg, scripts, dir, stats);
  const packaging = derivePackagingInfo(pkg, stats);

  return {
    deprecated,
    nodeEngine,
    requiredPeerDependencies,
    description,
    ...(typeof stats?.fileCount === 'number' ? { fileCount: stats.fileCount } : {}),
    hasBin,
    declaredDependencies,
    links,
    execution,
    ...(packaging ? { packaging } : {}),
    tsTypes
  };
}

function normalizeDeclaredDeps(source: any): Record<string, string> {
  if (!source || typeof source !== 'object') return {};
  const out: Record<string, string> = {};
  for (const [name, range] of Object.entries<any>(source)) {
    if (typeof name !== 'string' || !name.trim()) continue;
    if (typeof range !== 'string' || !range.trim()) continue;
    out[name] = range.trim();
  }
  return out;
}

function countRequiredPeerDependencies(
  peerDependencies: Record<string, string>,
  peerDependenciesMeta: any
): number {
  if (!peerDependencies || Object.keys(peerDependencies).length === 0) return 0;
  const meta = peerDependenciesMeta && typeof peerDependenciesMeta === 'object'
    ? peerDependenciesMeta
    : {};
  let count = 0;
  for (const peerName of Object.keys(peerDependencies)) {
    const peerMeta = meta[peerName];
    const optional = Boolean(
      peerMeta &&
      typeof peerMeta === 'object' &&
      peerMeta.optional === true
    );
    if (!optional) count += 1;
  }
  return count;
}

/**
 * Detects whether a package.json `bin` field indicates at least one executable target.
 *
 * @param binField - The `bin` value from a package.json (string or object)
 * @returns `true` if `binField` contains at least one non-empty string entry, `false` otherwise.
 */
function hasPackageBin(binField: any): boolean {
  if (typeof binField === 'string') return binField.trim().length > 0;
  if (!binField || typeof binField !== 'object') return false;
  return Object.values(binField).some((value) =>
    typeof value === 'string' && value.trim().length > 0
  );
}

/**
 * Normalize a package's `bundledDependencies` / `bundleDependencies` field into a canonical list.
 *
 * @param pkg - The package.json-like object to read bundling metadata from
 * @returns A sorted list of bundled package names. Returns `['*']` when bundling is declared as `true`, or an empty array when no bundled dependencies are specified.
 */
function normalizeBundledDependencies(pkg: any): string[] {
  if (pkg?.bundledDependencies === true || pkg?.bundleDependencies === true) {
    return ['*'];
  }
  const raw: unknown[] = Array.isArray(pkg?.bundledDependencies)
    ? pkg.bundledDependencies
    : Array.isArray(pkg?.bundleDependencies)
      ? pkg.bundleDependencies
      : [];
  const entries = raw
    .map((entry: unknown) => typeof entry === 'string' ? entry.trim() : '')
    .filter((entry): entry is string => entry.length > 0);
  return Array.from(new Set<string>(entries)).sort();
}

/**
 * Derives packaging-related signals from a package manifest and optional filesystem stats.
 *
 * @param pkg - The package.json object for the package being analyzed.
 * @param stats - Optional file-statistics for the package directory (e.g., presence of shrinkwrap).
 * @returns Packaging information containing `signals` (one or more of `bundled-dependencies` and `embedded-shrinkwrap`) and, when present, a `bundledDependencies` list; returns `undefined` when no packaging signals are detected.
 */
function derivePackagingInfo(
  pkg: any,
  stats: PackageStats | undefined
): DependencyRecord['packaging'] | undefined {
  const signals = new Set<PackagingSignal>();
  const bundledDependencies = normalizeBundledDependencies(pkg);
  if (bundledDependencies.length > 0) signals.add('bundled-dependencies');
  if (stats?.hasShrinkwrap) signals.add('embedded-shrinkwrap');
  const signalList = ['bundled-dependencies', 'embedded-shrinkwrap']
    .filter((signal): signal is PackagingSignal => signals.has(signal as PackagingSignal));
  if (signalList.length === 0) return undefined;
  return {
    signals: signalList,
    ...(bundledDependencies.length > 0 ? { bundledDependencies } : {})
  };
}

/**
 * Load and cache a package's package.json and its directory metadata.
 *
 * @param name - Package name to resolve
 * @param resolvePaths - Ordered list of base paths to use when resolving the package.json
 * @param cache - Map used to store and reuse previously loaded PackageMeta entries; keyed by `name` or `name@version`
 * @param version - Optional version hint used when resolving a specific package variant
 * @returns The `PackageMeta` containing the parsed `package.json` (`pkg`) and its directory (`dir`), or `undefined` if the package.json could not be resolved or read
 */
async function loadPackageMeta(
  name: string,
  resolvePaths: string[],
  cache: Map<string, PackageMeta>,
  version?: string
): Promise<PackageMeta | undefined> {
  const cacheKey = version ? `${name}@${version}` : name;
  if (cache.has(cacheKey)) return cache.get(cacheKey);
  try {
    const pkgJsonPath = await resolvePackageJsonPath(name, resolvePaths, version);
    if (!pkgJsonPath) return undefined;
    const pkgRaw = await fs.readFile(pkgJsonPath, 'utf8');
    const pkg = JSON.parse(pkgRaw);
    const meta = { pkg, dir: path.dirname(pkgJsonPath) };
    cache.set(cacheKey, meta);
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

/**
 * Collects filesystem-derived statistics for a package directory.
 *
 * Scans the package directory (best-effort) to detect whether the package
 * contains TypeScript declaration files, native binary artifacts, a
 * binding.gyp file, or an npm shrinkwrap file, and counts files. Nested
 * dependency stores (node_modules) and .git directories are ignored; I/O
 * errors are swallowed and the function returns whatever information could
 * be gathered.
 *
 * @param dir - Filesystem path to the package directory to inspect.
 * @param cache - Memoization map keyed by directory path; cached results are
 *                returned when available and new results are stored here.
 * @returns An object with:
 *          - `hasDts`: `true` when any `.d.ts` files were found.
 *          - `hasNativeBinary`: `true` when any `.node` binaries were found.
 *          - `hasBindingGyp`: `true` when a `binding.gyp` file was found.
 *          - `hasShrinkwrap`: `true` when an `npm-shrinkwrap.json` file was found.
 *          - `fileCount`: total number of regular files encountered under the directory.
 */
async function calculatePackageStats(dir: string, cache: Map<string, PackageStats>): Promise<PackageStats> {
  if (cache.has(dir)) return cache.get(dir)!;
  let hasDts = false;
  let hasNativeBinary = false;
  let hasBindingGyp = false;
  let hasShrinkwrap = false;
  let fileCount = 0;

  async function walk(current: string): Promise<void> {
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        // Ignore nested dependency stores to keep package-level stats bounded and comparable.
        if (entry.name === 'node_modules' || entry.name === '.git') continue;
        await walk(full);
      } else if (entry.isFile()) {
        fileCount += 1;
        if (entry.name.endsWith('.d.ts')) hasDts = true;
        if (entry.name.endsWith('.node')) hasNativeBinary = true;
        if (entry.name === 'binding.gyp') hasBindingGyp = true;
        if (entry.name === 'npm-shrinkwrap.json') hasShrinkwrap = true;
      }
    }
  }

  try {
    await walk(dir);
  } catch (err) {
    // best-effort; ignore inaccessible paths
  }
  const result: PackageStats = { hasDts, hasNativeBinary, hasBindingGyp, hasShrinkwrap, fileCount };
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
  try {
    const parsed = new URL(cleaned + hash);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return undefined;
    parsed.username = '';
    parsed.password = '';
    return parsed.toString();
  } catch {
    return undefined;
  }
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
const LOCAL_SIGNAL_MAX_FILES_PER_PACKAGE = 24;
const LOCAL_SIGNAL_MAX_BYTES_PER_FILE = 120_000;
const LOCAL_SIGNAL_MAX_PACKAGE_FILES = 2_000;
const COMPLEXITY_THRESHOLD = 12;

/**
 * Collects non-empty lifecycle hook commands from a package `scripts` object.
 *
 * @param scripts - The `scripts` section from a package.json (map of script names to values).
 * @returns An object mapping each lifecycle hook found in `scripts` to its trimmed command; only hooks defined in `LIFECYCLE_HOOKS` and with non-empty string values are included.
 */
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

/**
 * Finds the first Node script file path referenced by lifecycle hook commands, checking hooks in predefined order.
 *
 * @param lifecycleScripts - Map of lifecycle hook names to their command strings; only hooks with non-empty commands are inspected.
 * @returns The referenced script path (as found in a `node <script>` invocation) when present, `undefined` otherwise.
 */
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

/**
 * Normalize an input into a package-relative path by trimming whitespace and removing a leading `./` or `.\`.
 *
 * @param value - The input value to normalize (expected to be a path string)
 * @returns The cleaned package-relative path, or `undefined` if the input is not a string, is empty after trimming, or appears to be an absolute/URL (contains `://`)
 */
function normalizePackageRelativePath(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const cleaned = value.trim().replace(/^[.][/\\]/, '');
  if (!cleaned || cleaned.includes('://')) return undefined;
  return cleaned;
}

/**
 * Collects normalized executable entry targets from a package `bin` field.
 *
 * @param binField - The package `bin` field; may be a string or an object mapping executable names to paths.
 * @returns An array of normalized package-relative executable target paths, deduplicated and sorted.
 */
function packageBinTargets(binField: any): string[] {
  const targets = new Set<string>();
  const add = (value: unknown) => {
    const normalized = normalizePackageRelativePath(value);
    if (normalized) targets.add(normalized);
  };
  if (typeof binField === 'string') add(binField);
  else if (binField && typeof binField === 'object') {
    for (const value of Object.values(binField)) add(value);
  }
  return Array.from(targets).sort();
}

/**
 * Collects candidate entry file paths from a package manifest.
 *
 * Supports `main`, `module`, and `exports` fields, flattening arrays and objects and normalizing package-relative paths.
 *
 * @param pkg - The package.json object to read entry targets from
 * @returns An array of normalized package-relative entry paths, sorted; contains `index.js` when no entry fields are present
 */
function packageEntryTargets(pkg: any): string[] {
  const targets = new Set<string>();
  const add = (value: unknown) => {
    if (typeof value === 'string') {
      const normalized = normalizePackageRelativePath(value);
      if (normalized) targets.add(normalized);
      return;
    }
    if (Array.isArray(value)) {
      value.forEach(add);
      return;
    }
    if (value && typeof value === 'object') {
      Object.values(value).forEach(add);
    }
  };
  add(pkg?.main);
  add(pkg?.module);
  add(pkg?.exports);
  if (targets.size === 0) targets.add('index.js');
  return Array.from(targets).sort();
}

/**
 * Reads an install script file from a package directory if it is a regular file within size limits.
 *
 * @param scriptPath - The path to the script file as referenced in package scripts (resolved relative to `packageDir`)
 * @param packageDir - The package root directory used to resolve and bound `scriptPath`
 * @returns The file contents as UTF-8 text when the file exists inside `packageDir`, is a regular file, and its size is at most `INSTALL_SCRIPT_MAX_BYTES`; `undefined` otherwise.
 */
async function readInstallScriptFile(
  scriptPath: string,
  packageDir: string
): Promise<string | undefined> {
  const resolvedDir = path.resolve(packageDir);
  const resolvedPath = path.resolve(resolvedDir, scriptPath);
  if (!resolvedPath.startsWith(resolvedDir + path.sep)) return undefined;
  // Stat and read through one handle so the checked file and the read file
  // cannot differ (avoids a check-then-use race on the path).
  let handle: import('fs/promises').FileHandle | undefined;
  try {
    handle = await fs.open(resolvedPath, 'r');
    const stat = await handle.stat();
    if (!stat.isFile()) return undefined;
    return await readHandleCapped(handle, INSTALL_SCRIPT_MAX_BYTES);
  } catch {
    return undefined;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/**
 * Read at most `maxBytes` from an open handle, enforcing the cap during the
 * read itself so a file that grows after being stat'ed cannot exceed it.
 *
 * @returns The UTF-8 content, or `undefined` when the file exceeds `maxBytes`.
 */
async function readHandleCapped(
  handle: import('fs/promises').FileHandle,
  maxBytes: number
): Promise<string | undefined> {
  const cap = maxBytes + 1;
  const buffer = Buffer.alloc(cap);
  let offset = 0;
  while (offset < cap) {
    const { bytesRead } = await handle.read(buffer, offset, cap - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset > maxBytes) return undefined;
  return buffer.subarray(0, offset).toString('utf8');
}

/**
 * Checks whether a file path refers to an inspectable source file used for static analysis.
 *
 * @param filePath - The file path to test (relative or absolute)
 * @returns `true` if the path ends with a JS/TS-related extension (`.js`, `.cjs`, `.mjs`, `.jsx`, `.ts`, `.tsx`) or has no extension, `false` otherwise.
 */
function isInspectableSourcePath(filePath: string): boolean {
  return /\.(?:js|cjs|mjs|jsx|ts|tsx)$/i.test(filePath) || path.extname(filePath) === '';
}

/**
 * Detects whether a JavaScript-like file is likely minified or otherwise obfuscated.
 *
 * Uses filename and simple content heuristics to identify minified files.
 *
 * @param fileName - The file name or path (used to detect `.min.js/.min.cjs/.min.mjs` suffixes)
 * @param text - The file contents to inspect
 * @returns `true` if the file appears minified or obfuscated, `false` otherwise.
 */
function looksMinified(fileName: string, text: string): boolean {
  if (/\.min\.(?:js|cjs|mjs)$/i.test(fileName)) return true;
  const lines = text.split(/\r?\n/);
  if (lines.length <= 3 && text.length > 20_000) return true;
  return lines.some((line) => line.length > 10_000);
}

/**
 * Determine whether a string appears to be readable text (not binary or overwhelmingly control-character data).
 *
 * Empty strings are considered text; presence of a NUL character marks the input as non-text. The function treats
 * the input as text when the proportion of suspicious control or replacement characters is less than 1%.
 *
 * @param text - The string to evaluate
 * @returns `true` if the input appears to be readable text, `false` otherwise.
 */
function looksTextLike(text: string): boolean {
  if (text.includes('\0')) return false;
  if (text.length === 0) return true;
  const suspicious = (text.match(/[\uFFFD\x00-\x08\x0E-\x1F]/g) || []).length;
  return suspicious / text.length < 0.01;
}

/**
 * Detects whether a text blob appears to be JavaScript or Node.js source.
 *
 * @param text - The text to inspect for JavaScript/Node indicators
 * @returns `true` if the text contains common JavaScript or Node.js source markers (shebang with `node`, `require(`, `import`, `module.exports`, or `process.`), `false` otherwise
 */
function looksJavaScriptLike(text: string): boolean {
  return (
    /^#!.*\bnode\b/.test(text) ||
    /\brequire\s*\(/.test(text) ||
    /\bimport\s+/.test(text) ||
    /\bmodule\.exports\b/.test(text) ||
    /\bprocess\./.test(text)
  );
}

/**
 * Read and return the text of a package-relative source file when it is safe and useful to inspect.
 *
 * Attempts to resolve and read `filePath` inside `packageDir` and returns the file contents only if the file:
 * - resides within `packageDir`,
 * - matches the allowed inspectable source path patterns,
 * - is a regular file whose size does not exceed `maxBytes`,
 * - appears to be text (and, for extensionless files, looks like JavaScript),
 * - does not appear minified or otherwise obfuscated.
 *
 * @param filePath - Path to the candidate file relative to the package directory
 * @param packageDir - Absolute path of the package root to constrain reads
 * @param maxBytes - Maximum number of bytes to read from the file (per-file size limit)
 * @returns The file content when it is inspectable under the above constraints, `undefined` otherwise
 */
async function readInspectablePackageFile(
  filePath: string,
  packageDir: string,
  maxBytes = LOCAL_SIGNAL_MAX_BYTES_PER_FILE
): Promise<string | undefined> {
  const resolvedDir = path.resolve(packageDir);
  const resolvedPath = path.resolve(resolvedDir, filePath);
  if (!resolvedPath.startsWith(resolvedDir + path.sep)) return undefined;
  if (!isInspectableSourcePath(resolvedPath)) return undefined;
  // Stat and read through one handle so the checked file and the read file
  // cannot differ (avoids a check-then-use race on the path).
  let handle: import('fs/promises').FileHandle | undefined;
  try {
    handle = await fs.open(resolvedPath, 'r');
    const stat = await handle.stat();
    if (!stat.isFile()) return undefined;
    const text = await readHandleCapped(handle, maxBytes);
    if (text === undefined) return undefined;
    if (!looksTextLike(text)) return undefined;
    if (path.extname(resolvedPath) === '' && !looksJavaScriptLike(text)) return undefined;
    if (looksMinified(resolvedPath, text)) return undefined;
    return text;
  } catch {
    return undefined;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/**
 * Collects a bounded list of inspectable source file paths inside a package directory.
 *
 * Traverses the package tree (skipping symlinks and common non-source directories) and returns
 * a sorted array of package-relative paths for files considered inspectable.
 *
 * @param packageDir - Absolute path to the package directory to scan
 * @param maxFiles - Maximum number of inspectable file paths to return
 * @param maxPackageFiles - Maximum number of files to examine within the package (counts all files visited)
 * @returns A sorted array of relative file paths (relative to `packageDir`) for inspectable source files
 */
async function collectBoundedInspectableFiles(
  packageDir: string,
  maxFiles: number,
  maxPackageFiles: number
): Promise<string[]> {
  const out: string[] = [];
  let seen = 0;
  async function walk(current: string): Promise<void> {
    if (out.length >= maxFiles || seen >= maxPackageFiles) return;
    const entries = await fs.readdir(current, { withFileTypes: true }).catch(() => []);
    entries.sort((a, b) => a.name.localeCompare(b.name, 'en', { numeric: true, sensitivity: 'base' }));
    for (const entry of entries) {
      if (out.length >= maxFiles || seen >= maxPackageFiles) return;
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'test' || entry.name === 'tests' || entry.name === 'docs') continue;
        await walk(full);
      } else if (entry.isFile()) {
        seen += 1;
        if (isInspectableSourcePath(full)) {
          out.push(path.relative(packageDir, full));
        }
      }
    }
  }
  await walk(packageDir);
  return out.sort();
}

/**
 * Identify execution-related static signals present in a block of source or script text.
 *
 * @param text - The file or lifecycle script text to analyze for execution signals
 * @returns An ordered array of distinct execution signals detected in `text`, prioritized according to the canonical execution-signal ordering
 */
export function detectLocalExecutionSignals(text: string): ExecutionSignal[] {
  const signals = new Set<ExecutionSignal>();
  detectFileSignals(text, signals);
  return EXECUTION_SIGNAL_ORDER.filter((signal) => signals.has(signal));
}

/**
 * Checks whether the given text matches any regular expression in the provided list.
 *
 * @param text - The string to test against the patterns
 * @param patterns - Array of `RegExp` objects to test
 * @returns `true` if at least one pattern matches `text`, `false` otherwise.
 */
function textHasAny(text: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(text));
}

/**
 * Detects install-time script characteristics from a text blob and adds matching execution signals to the provided set.
 *
 * Examines the input text with heuristics for common patterns and adds any of the following `ExecutionSignal` values to `signals` when matched:
 * - `network-access` — patterns that fetch remote resources (curl, wget, http(s), fetch, axios, net.connect, dns, etc.).
 * - `reads-env` — access to environment variables or printenv-style usage.
 * - `reads-home` — references to user home paths or APIs returning the home directory.
 * - `uses-ssh` — references to SSH-related files, agents, or SSH/git configuration.
 *
 * @param text - The script or file text to statically inspect for indicative patterns.
 * @param signals - A mutable Set that will receive any detected execution signals.
 */
function detectScriptSignals(text: string, signals: Set<ExecutionSignal>): void {
  // Signals are derived from static text inspection only: no code execution and no import walking.
  // They are NOT malware detection; they merely highlight review-worthy install-time behavior.

  // "network-access" surfaces install scripts that fetch remote resources (review for expected downloads; does NOT imply exfiltration).
  if (textHasAny(text, [/\bcurl\b/i, /\bwget\b/i, /https?:\/\//i, /\bfetch\s*\(/i, /\baxios\b/i, /node-fetch/i, /\bhttps?\.request\s*\(/, /\bnet\.connect\s*\(/, /\bdns\./])) {
    signals.add('network-access');
  }
  // "reads-env" highlights environment access (does NOT imply exfiltration).
  if (textHasAny(text, [/\bprocess\.env\b/, /\bprintenv\b/i, /\benv\s*\|/i])) {
    signals.add('reads-env');
  }
  // "reads-home" highlights access to user home paths (does NOT imply credential theft).
  if (textHasAny(text, [/\$HOME\b/, /process\.env\.HOME\b/, /\bUSERPROFILE\b/, /os\.homedir\s*\(/, /~\//, /\/Users\//, /\/home\//])) {
    signals.add('reads-home');
  }
  // "uses-ssh" flags access to SSH-related paths (does NOT imply key exfiltration).
  if (textHasAny(text, [/\.ssh\b/i, /id_rsa\b/i, /known_hosts\b/i, /ssh-key/i, /ssh-agent/i, /GIT_SSH_COMMAND\b/, /\.npmrc\b/i])) {
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

/**
 * Detects static execution- and obfuscation-related signals from a JavaScript file's text and adds them to `signals`.
 *
 * Scans the provided source text for review cues such as script-level indicators, dynamic code execution APIs, child-process usage, explicit encoding patterns, and signs of obfuscation/minification. Matches are added to the supplied `signals` set; the function does not return a value and does not imply malicious intent by itself.
 *
 * @param text - The source text of a JavaScript file to analyze.
 * @param signals - A mutable set that will be populated with discovered `ExecutionSignal` values.
 */
function detectFileSignals(text: string, signals: Set<ExecutionSignal>): void {
  // Signals from a single directly-referenced JS file (no execution, no imports, no deep scanning).
  // These are review cues only and do NOT imply malicious intent.
  detectScriptSignals(text, signals);

  // "dynamic-exec" flags dynamic code execution APIs (does NOT imply malicious behavior).
  if (textHasAny(text, [/\beval\s*\(/, /new\s+Function\s*\(/, /\bvm\.runIn/i])) {
    signals.add('dynamic-exec');
  }
  // "child-process" flags process spawning (does NOT imply abuse).
  if (textHasAny(text, [/\bchild_process\b/, /\bexec\s*\(/, /\bspawn\s*\(/, /\bexecFile\s*\(/, /\bexecSync\s*\(/, /\bspawnSync\s*\(/])) {
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

/**
 * Classifies execution-related risk level for a package based on lifecycle scripts, detected signals, and script complexity.
 *
 * @param hasScripts - Whether the package defines any lifecycle scripts
 * @param hasSignals - Whether static analysis detected execution-related signals (network, child-process, dynamic execution, etc.)
 * @param highComplexity - Whether the package's lifecycle scripts exceed the complexity threshold
 * @param hooks - Lifecycle hooks present (note: `install` or `postinstall` count as install-time hooks)
 * @returns `'red'` when scripts are present and either execution signals exist or scripts are highly complex on an install-time hook; `'amber'` otherwise.
 */
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

/**
 * Collects execution-related static signals from a package's likely entry and inspectable source files using bounded, best-effort inspection.
 *
 * This inspects candidate entry points (e.g., `bin`, `main`, `module`, `exports`) plus a bounded set of other inspectable files, applies static detectors, and returns the detected execution signals in the canonical ordering.
 *
 * @param pkg - The package.json object for the package being inspected.
 * @param packageDir - The package filesystem directory to read files from; when `undefined`, the function returns an empty array.
 * @param options.maxFiles - Maximum number of files to inspect (default: LOCAL_SIGNAL_MAX_FILES_PER_PACKAGE).
 * @param options.maxBytesPerFile - Maximum bytes to read per file (default: LOCAL_SIGNAL_MAX_BYTES_PER_FILE).
 * @param options.maxPackageFiles - Maximum number of candidate package files to enumerate before selecting up to `maxFiles` for inspection (default: LOCAL_SIGNAL_MAX_PACKAGE_FILES).
 * @returns An array of detected `ExecutionSignal` values, ordered according to the canonical `EXECUTION_SIGNAL_ORDER`. Empty if no signals are found.
 */
export async function collectPackageExecutionSignals(
  pkg: any,
  packageDir: string | undefined,
  options: {
    maxFiles?: number;
    maxBytesPerFile?: number;
    maxPackageFiles?: number;
  } = {}
): Promise<ExecutionSignal[]> {
  if (!packageDir) return [];
  const maxFiles = options.maxFiles ?? LOCAL_SIGNAL_MAX_FILES_PER_PACKAGE;
  const maxBytesPerFile = options.maxBytesPerFile ?? LOCAL_SIGNAL_MAX_BYTES_PER_FILE;
  const maxPackageFiles = options.maxPackageFiles ?? LOCAL_SIGNAL_MAX_PACKAGE_FILES;
  const candidateFiles = new Set<string>();
  for (const file of [...packageBinTargets(pkg?.bin), ...packageEntryTargets(pkg)]) {
    candidateFiles.add(file);
  }
  for (const file of await collectBoundedInspectableFiles(packageDir, maxFiles, maxPackageFiles)) {
    candidateFiles.add(file);
    if (candidateFiles.size >= maxFiles) break;
  }

  const signals = new Set<ExecutionSignal>();
  let inspected = 0;
  for (const file of candidateFiles) {
    if (inspected >= maxFiles) break;
    const text = await readInspectablePackageFile(file, packageDir, maxBytesPerFile);
    if (!text) continue;
    inspected += 1;
    detectFileSignals(text, signals);
  }
  return EXECUTION_SIGNAL_ORDER.filter((signal) => signals.has(signal));
}

/**
 * Derives install-time execution signals, script metadata, and a consolidated execution risk for a package.
 *
 * Analyzes lifecycle hooks, referenced install scripts, native-build indicators, and bounded package file inspection to produce ordered execution signals, an execution complexity score when applicable, and a risk classification. Returns undefined when no meaningful execution signals, scripts, or native indicators are present.
 *
 * @param pkg - The package.json object for the dependency; used to locate entry points and candidate files for inspection.
 * @param scripts - The package's lifecycle `scripts` map (from package.json).
 * @param packageDir - Absolute path to the package directory used for reading referenced install scripts and package files; when undefined, file-based inspection is skipped.
 * @param stats - Optional PackageStats containing file-based heuristics (e.g., `hasNativeBinary`, `hasBindingGyp`) used as native indicators.
 * @returns An execution record containing:
 *  - `risk`: computed execution risk,
 *  - optional `native`: `true` when native-build indicators are present,
 *  - optional `signals`: ordered list of detected execution signals,
 *  - optional `scripts`: metadata about lifecycle hooks including `hooks`, optional `complexity`, and optional script-only `signals`.
 */
async function deriveExecutionInfo(
  pkg: any,
  scripts: Record<string, any>,
  packageDir: string | undefined,
  stats: PackageStats | undefined
): Promise<DependencyRecord['execution'] | undefined> {
  const lifecycleScripts = collectLifecycleScripts(scripts);
  const hooks = LIFECYCLE_HOOKS.filter((hook) => Boolean(lifecycleScripts[hook]));
  const hasScripts = hooks.length > 0;
  const hasNative = Boolean(stats?.hasNativeBinary || stats?.hasBindingGyp || scriptsContainNativeTooling(scripts));

  const scriptSignals = new Set<ExecutionSignal>();
  const combinedScripts = hooks.map((hook) => lifecycleScripts[hook]!).join('\n');
  if (combinedScripts) {
    detectScriptSignals(combinedScripts, scriptSignals);
  }

  if (hasScripts && packageDir) {
    const referencedScript = findReferencedInstallScript(lifecycleScripts);
    if (referencedScript) {
      const fileContent = await readInstallScriptFile(referencedScript, packageDir);
      if (fileContent) {
        detectFileSignals(fileContent, scriptSignals);
      }
    }
  }

  const packageSignals = await collectPackageExecutionSignals(pkg, packageDir);
  const allSignals = new Set<ExecutionSignal>([...scriptSignals, ...packageSignals]);

  const complexityScore = hasScripts ? scoreLifecycleScripts(lifecycleScripts) : 0;
  const complexity = complexityScore >= COMPLEXITY_THRESHOLD ? complexityScore : undefined;

  const scriptSignalList = EXECUTION_SIGNAL_ORDER.filter((signal) => scriptSignals.has(signal));
  const signalList = EXECUTION_SIGNAL_ORDER.filter((signal) => allSignals.has(signal));

  if (!hasScripts && !hasNative && signalList.length === 0) return undefined;

  const scriptsInfo: NonNullable<DependencyRecord['execution']>['scripts'] = {
    hooks,
    ...(complexity !== undefined ? { complexity } : {}),
    ...(scriptSignalList.length > 0 ? { signals: scriptSignalList } : {})
  };

  const risk = determineExecutionRisk(hasScripts, signalList.length > 0, complexity !== undefined, hooks);
  const execution: DependencyRecord['execution'] = { risk };
  // Native is surface description only; not a behavioral signal.
  if (hasNative) execution.native = true;
  if (signalList.length > 0) execution.signals = signalList;
  if (hasScripts) execution.scripts = scriptsInfo;
  return execution;
}
