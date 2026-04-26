export type Severity = 'low' | 'moderate' | 'high' | 'critical';
export type OutdatedStatus = 'current' | 'patch' | 'minor' | 'major' | 'unknown';
export type PackageManager = 'npm' | 'pnpm' | 'yarn';

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

// Sparse install-time execution signals only; absence means "nothing runs automatically".
// Signals are behavioral hints, not malware classification, and no code is executed.
export interface DependencyExecutionInfo {
  risk: 'amber' | 'red';
  // Native compilation/tooling surface only (not a behavioral signal).
  native?: true;
  scripts?: {
    hooks: ExecutionHook[];
    complexity?: number;
    signals?: ExecutionSignal[];
  };
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
  };
  // Usage answers why this dependency exists and where it shows up in the project.
  usage: {
    direct: boolean;
    scope: 'runtime' | 'dev' | 'optional' | 'peer';
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
}

export type FindingSeverity = 'info' | 'warning' | 'error';
export type FindingCategory =
  | 'security'
  | 'license'
  | 'execution'
  | 'upgrade'
  | 'supply-chain';

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

export interface ToolResult<T> {
  ok: boolean;
  data?: T;
  error?: string;
  file?: string;
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
  schemaVersion: '1.4';
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
  findings?: DependencyFinding[];
  dependencies: Record<string, DependencyRecord>;
}

export interface ScanOptions {
  projectPath: string;
  tempDir: string;
  outputPath: string;
  keepTemp?: boolean;
}
