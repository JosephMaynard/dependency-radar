export type Severity = 'low' | 'moderate' | 'high' | 'critical';
export type OutdatedStatus = 'current' | 'patch' | 'minor' | 'major' | 'unknown';
export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'bun';
export type ScanCollectorStatus = 'available' | 'partial' | 'unavailable' | 'skipped';
export type ScanCollectorName =
  | 'dependencyTree'
  | 'audit'
  | 'imports'
  | 'maintenance'
  | 'registryMetadata'
  | 'supplyChain';

export interface ScanStatus {
  complete: boolean;
  collectors: Record<ScanCollectorName, ScanCollectorStatus>;
  warnings: string[];
}

export interface VulnerabilityAdvisory {
  id: string;
  title: string;
  severity: Severity;
  vulnerableRange: string;
  fixAvailable: boolean;
  url: string;
}

export interface VulnerabilitySummary {
  counts: Record<Severity, number>;
  highestSeverity: Severity | 'none';
  risk: 'green' | 'amber' | 'red';
  advisories?: VulnerabilityAdvisory[];
}

export interface DependencyOrigins {
  rootPackageCount: number;
  topRootPackages: Array<{ name: string; version: string }>;
  parentPackageCount: number;
  topParentPackages: string[];
  workspaces?: string[];
}

export type SubDependencyEntry = [string, string | null];

export interface SubDependencyMap {
  dep?: Record<string, SubDependencyEntry>;
  dev?: Record<string, SubDependencyEntry>;
  opt?: Record<string, SubDependencyEntry>;
  peer?: Record<string, SubDependencyEntry>;
}

export type ExecutionHook = 'preinstall' | 'install' | 'postinstall' | 'prepare';
export type ExecutionSignal =
  | 'network-access'
  | 'dynamic-exec'
  | 'child-process'
  | 'encoding'
  | 'obfuscated'
  | 'reads-env'
  | 'reads-home'
  | 'uses-ssh';

export type PackagingSignal =
  | 'bundled-dependencies'
  | 'embedded-shrinkwrap';

export type RegistryRiskSignal =
  | 'recent-package'
  | 'recent-version'
  | 'low-release-history'
  | 'reactivated-package'
  | 'old-major-new-patch';

// Sparse local execution signals only; absence means no signal was detected by bounded static inspection.
// Signals are behavioral hints, not malware classification, and no code is executed.
export interface DependencyExecutionInfo {
  risk: 'amber' | 'red';
  // Native compilation/tooling surface only (not a behavioral signal).
  native?: true;
  // Signals from lifecycle scripts, bin targets, entry files, or a small bounded set of package JS files.
  signals?: ExecutionSignal[];
  scripts?: {
    hooks: ExecutionHook[];
    complexity?: number;
    // Backward-compatible install-time subset of signals found in lifecycle commands or referenced install files.
    signals?: ExecutionSignal[];
  };
}

export interface DependencyPackagingInfo {
  signals: PackagingSignal[];
  bundledDependencies?: string[];
}

export interface DependencyRegistryEnrichment {
  attempted: true;
  ok: boolean;
  source: 'npm-registry';
  candidateReasons: string[];
  packageCreatedAt?: string;
  packageModifiedAt?: string;
  installedVersionPublishedAt?: string;
  latestVersion?: string;
  latestPublishedAt?: string;
  versionCount?: number;
  distTags?: Record<string, string>;
  signals?: RegistryRiskSignal[];
  error?: string;
}

export interface DependencySupplyChainInfo {
  registry?: DependencyRegistryEnrichment;
}

// Community-suggested replacement from the e18e module-replacements
// catalogue (https://github.com/es-tooling/module-replacements), matched
// offline against vendored data. Guidance, not policy.
export interface DependencyReplacementInfo {
  source: 'e18e-module-replacements';
  manifest: 'native' | 'micro-utilities' | 'preferred';
  type: 'native' | 'documented' | 'simple';
  replacements: string[];
  docUrl?: string;
}

export type UpgradeRisk = 'high' | 'medium' | 'low' | 'unknown';

export type DependencyScope = 'runtime' | 'dev' | 'optional' | 'peer';

/**
 * Scopes that install and execute in production. Optional dependencies are
 * skipped only when they fail to build — when present they run exactly like
 * runtime dependencies, so production policies must include them.
 */
export function isProductionScope(scope: DependencyScope): boolean {
  return scope === 'runtime' || scope === 'optional';
}

export type MaintenanceStatus =
  | 'deprecated'
  | 'archived'
  | 'unmaintained'
  | 'stale'
  | 'slowing'
  | 'active'
  | 'unknown';

// Registry-derived maintenance signals. Conservative review cues, not verdicts:
// `packageModifiedAt` comes from the packument `modified` timestamp, which
// updates on ANY registry write, so age-based statuses under-flag rather than
// over-flag. Data is fetched best-effort; scans never fail because of it.
export interface DependencyMaintenanceInfo {
  attempted: true;
  ok: boolean;
  status: MaintenanceStatus;
  deprecated?: {
    installedVersion: boolean;
    latestVersion: boolean;
    message?: string;
  };
  repoArchived?: boolean;
  repoCheckedAt?: string;
  repoPushedAt?: string;
  monthsSinceRepoPush?: number;
  packageModifiedAt?: string;
  monthsSinceModified?: number;
  latestVersion?: string;
  fetchedAt?: string;
  fromCache?: true;
  error?: string;
}

export type LicenseConfidence = 'high' | 'medium' | 'low';
export type LicenseStatus =
  | 'declared-only'
  | 'inferred-only'
  | 'match'
  | 'mismatch'
  | 'invalid-spdx'
  | 'unknown';

export interface DependencyLicenseInfo {
  declared?: {
    spdxId: string;
    expression: boolean;
    deprecated: boolean;
    valid: boolean;
  };
  inferred?: {
    spdxId: string;
    confidence: LicenseConfidence;
  };
  exception?: {
    id: string;
    deprecated: boolean;
    valid: boolean;
  };
  status: LicenseStatus;
}

// Grouped by human review questions (what it is, security, usage, graph impact, execution).
export interface DependencyRecord {
  package: {
    id: string;
    name: string;
    version: string;
    description?: string;
    // Number of files observed in the installed package directory (excluding nested node_modules).
    fileCount?: number;
    // True when the package exposes at least one CLI executable via package.json#bin.
    hasBin?: true;
    deprecated: boolean;
    links: {
      npm: string;
      repository?: string;
      homepage?: string;
      bugs?: string;
    };
  };
  compliance: {
    license: DependencyLicenseInfo;
    licenseRisk: 'green' | 'amber' | 'red';
  };
  security: {
    // Summary answers "is this risky?" while advisories answer "why is this risky?"
    // Advisories are disclosed findings; dropping them is a data loss bug.
    summary: {
      critical: number;
      high: number;
      moderate: number;
      low: number;
      highest: Severity | 'none';
      risk: 'green' | 'amber' | 'red';
    };
    advisories?: VulnerabilityAdvisory[];
  };
  upgrade: {
    nodeEngine: string | null;
    outdatedStatus?: OutdatedStatus;
    latestVersion?: string;
    blockers?: Array<'nodeEngine' | 'peerDependency' | 'nativeBindings' | 'installScripts' | 'deprecated'>;
    blocksNodeMajor?: boolean;
    targetNodeCompatible?: boolean;
    // Derived from outdated status and blockers; recomputed after registry
    // enrichment so a registry-discovered deprecation is reflected.
    risk?: UpgradeRisk;
  };
  // Usage answers why this dependency exists and where it shows up in the project.
  usage: {
    direct: boolean;
    scope: DependencyScope;
    depth: number;
    origins: DependencyOrigins;
    introduction?: 'direct' | 'tooling' | 'framework' | 'testing' | 'transitive' | 'unknown';
    runtimeImpact?: 'runtime' | 'build' | 'testing' | 'tooling' | 'mixed';
    importUsage?: {
      fileCount: number;
      topFiles: string[];
    };
    tsTypes: 'bundled' | 'definitelyTyped' | 'none' | 'unknown';
  };
  // Graph answers blast-radius questions (who depends on it, and what it pulls in).
  graph: {
    fanIn: number;
    fanOut: number;
    subDeps?: SubDependencyMap;
  };
  execution?: DependencyExecutionInfo;
  packaging?: DependencyPackagingInfo;
  supplyChain?: DependencySupplyChainInfo;
  maintenance?: DependencyMaintenanceInfo;
  replacement?: DependencyReplacementInfo;
}

export type FindingSeverity = 'info' | 'warning' | 'error';
export type FindingCategory =
  | 'security'
  | 'license'
  | 'execution'
  | 'upgrade'
  | 'supply-chain'
  | 'modernization';

export interface DependencyFinding {
  id: string;
  category: FindingCategory;
  severity: FindingSeverity;
  packageId: string;
  packageName: string;
  packageVersion: string;
  title: string;
  message: string;
  evidence?: string;
  recommendation?: string;
}

export type SupplyChainSignalType =
  | 'git-dependency'
  | 'file-dependency'
  | 'non-registry-tarball'
  | 'missing-integrity'
  | 'unexpected-registry-host';

export interface SupplyChainSignal {
  type: SupplyChainSignalType;
  packageName?: string;
  packageVersion?: string;
  packageId?: string;
  source: string;
  detail: string;
}

export interface SupplyChainSummary {
  signals: SupplyChainSignal[];
  signatureAudit?: {
    attempted: boolean;
    ok: boolean;
    status?: 'verified' | 'failed' | 'skipped';
    output?: string;
    error?: string;
  };
}

export interface ToolResult<T> {
  ok: boolean;
  status?: 'skipped';
  data?: T;
  error?: string;
  file?: string;
  // Working directory used when relative paths in collector output need to be
  // reconciled with the installed dependency graph.
  contextPath?: string;
}

export interface OutdatedEntry {
  name: string;
  currentVersion: string;
  status: Exclude<OutdatedStatus, 'current'>;
  latestVersion?: string;
}

export interface OutdatedResult {
  entries: OutdatedEntry[];
  unknownNames: string[];
}

export interface WorkspacePackage {
  name: string;
  relativePath: string;
  directExternal: {
    runtime: number;
    dev: number;
  };
}

export interface ProjectDependencyPolicy {
  overrides?: Record<string, unknown>;
  resolutions?: Record<string, unknown>;
}

export interface ProjectDependencyPolicySummary {
  hasOverrides: boolean;
  overrideCount: number;
  overriddenPackageNames?: string[];
  hasResolutions: boolean;
  resolutionCount: number;
  resolvedPackageNames?: string[];
  sources?: string[];
}

export interface AggregatedData {
  schemaVersion: '1.7';
  generatedAt: string;
  dependencyRadarVersion: string;
  git: {
    branch: string;
  };
  project: {
    projectDir: string;
    name?: string;
    version?: string;
    description?: string;
    license?: string;
    keywords?: string[];
    homepage?: string;
    repository?: string;
    constraints?: {
      os?: string[];
      cpu?: string[];
      enginesNode?: string;
    };
    dependencyPolicy?: ProjectDependencyPolicy;
    dependencyPolicySummary?: ProjectDependencyPolicySummary;
  };
  environment: {
    nodeVersion: string;
    runtimeVersion: string;
    minRequiredMajor: number;
    targetNodeMajor?: number;
    platform?: string;
    arch?: string;
    ci?: boolean;
    packageManagerField?: string;
    packageManager?: PackageManager;
    packageManagerVersion?: string;
    toolVersions?: {
      npm?: string;
      pnpm?: string;
      yarn?: string;
      bun?: string;
    };
  };
  workspaces: {
    enabled: boolean;
    type?: PackageManager | 'none';
    packageCount?: number;
    workspacePackages?: WorkspacePackage[];
  };
  summary: {
    dependencyCount: number;
    directCount: number;
    transitiveCount: number;
    findingCount?: number;
  };
  scanStatus?: ScanStatus;
  supplyChain?: SupplyChainSummary;
  findings?: DependencyFinding[];
  dependencies: Record<string, DependencyRecord>;
}

export interface ScanOptions {
  projectPath: string;
  tempDir: string;
  outputPath: string;
  keepTemp?: boolean;
}
