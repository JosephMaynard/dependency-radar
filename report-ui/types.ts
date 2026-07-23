// Client-side types matching src/types.ts
// These are used for the report UI rendering

export type Severity = 'low' | 'moderate' | 'high' | 'critical';
export type OutdatedStatus = 'current' | 'patch' | 'minor' | 'major' | 'unknown';
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

export interface VulnerabilityAdvisory {
  id: string;
  title: string;
  severity: Severity;
  vulnerableRange: string;
  fixAvailable: boolean;
  url: string;
}

export interface DependencyRecord {
  package: {
    id: string;
    name: string;
    version: string;
    description?: string;
    fileCount?: number;
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
    risk?: 'high' | 'medium' | 'low' | 'unknown';
  };
  usage: {
    direct: boolean;
    scope: 'runtime' | 'dev' | 'optional' | 'peer';
    depth: number;
    origins: {
      workspaces?: string[];
      rootPackageCount: number;
      topRootPackages: Array<{ name: string; version: string } | string>;
      parentPackageCount: number;
      topParentPackages: string[];
    };
    introduction?: 'direct' | 'tooling' | 'framework' | 'testing' | 'transitive' | 'unknown';
    runtimeImpact?: 'runtime' | 'build' | 'testing' | 'tooling' | 'mixed';
    importUsage?: {
      fileCount: number;
      topFiles: string[];
    };
    tsTypes: 'bundled' | 'definitelyTyped' | 'none' | 'unknown';
  };
  graph: {
    fanIn: number;
    fanOut: number;
    subDeps?: {
      dep?: Record<string, [string, string | null]>;
      dev?: Record<string, [string, string | null]>;
      opt?: Record<string, [string, string | null]>;
      peer?: Record<string, [string, string | null]>;
    };
  };
  execution?: {
    risk: 'amber' | 'red';
    native?: true;
    signals?: ExecutionSignal[];
    scripts?: {
      hooks: ExecutionHook[];
      complexity?: number;
      signals?: ExecutionSignal[];
    };
  };
  packaging?: {
    signals: PackagingSignal[];
    bundledDependencies?: string[];
  };
  supplyChain?: {
    registry?: {
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
    };
  };
  maintenance?: {
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
  };
  replacement?: {
    source: 'e18e-module-replacements';
    manifest: 'native' | 'micro-utilities' | 'preferred';
    type: 'native' | 'documented' | 'simple';
    replacements: string[];
    docUrl?: string;
  };
}

export type MaintenanceStatus =
  | 'deprecated'
  | 'archived'
  | 'unmaintained'
  | 'stale'
  | 'slowing'
  | 'active'
  | 'unknown';

export interface AggregatedData {
  schemaVersion: '1.2' | '1.3' | '1.4' | '1.5' | '1.6' | '1.7';
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
    dependencyPolicy?: {
      overrides?: Record<string, unknown>;
      resolutions?: Record<string, unknown>;
    };
    dependencyPolicySummary?: {
      hasOverrides: boolean;
      overrideCount: number;
      overriddenPackageNames?: string[];
      hasResolutions: boolean;
      resolutionCount: number;
      resolvedPackageNames?: string[];
      sources?: string[];
    };
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
    packageManager?: 'npm' | 'pnpm' | 'yarn' | 'bun';
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
    type?: 'npm' | 'pnpm' | 'yarn' | 'bun' | 'none';
    packageCount?: number;
    workspacePackages?: Array<{
      name: string;
      relativePath: string;
      directExternal: {
        runtime: number;
        dev: number;
      };
    }>;
  };
  scanStatus?: {
    complete: boolean;
    collectors: {
      dependencyTree: 'available' | 'partial' | 'unavailable' | 'skipped';
      audit: 'available' | 'partial' | 'unavailable' | 'skipped';
      imports: 'available' | 'partial' | 'unavailable' | 'skipped';
      maintenance: 'available' | 'partial' | 'unavailable' | 'skipped';
      registryMetadata: 'available' | 'partial' | 'unavailable' | 'skipped';
      supplyChain: 'available' | 'partial' | 'unavailable' | 'skipped';
    };
    warnings: string[];
  };
  supplyChain?: {
    signals: Array<{
      type: string;
      packageName?: string;
      packageVersion?: string;
      packageId?: string;
      source: string;
      detail: string;
    }>;
    signatureAudit?: {
      attempted: boolean;
      ok: boolean;
      status?: 'verified' | 'failed' | 'skipped';
      output?: string;
      error?: string;
    };
  };
  summary: {
    dependencyCount: number;
    directCount: number;
    transitiveCount: number;
    findingCount?: number;
  };
  findings?: Array<{
    id: string;
    category: string;
    severity: 'info' | 'warning' | 'error';
    packageId: string;
    packageName: string;
    packageVersion: string;
    title: string;
    message: string;
    evidence?: string;
    recommendation?: string;
  }>;
  dependencies: Record<string, DependencyRecord>;
}
