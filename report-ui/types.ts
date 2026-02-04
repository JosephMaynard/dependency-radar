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
    blockers?: Array<'nodeEngine' | 'peerDependency' | 'nativeBindings' | 'deprecated'>;
    blocksNodeMajor?: boolean;
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
    scripts?: {
      hooks: ExecutionHook[];
      complexity?: number;
      signals?: ExecutionSignal[];
    };
  };
}

export interface AggregatedData {
  schemaVersion: '1.2';
  generatedAt: string;
  dependencyRadarVersion: string;
  git: {
    branch: string;
  };
  project: {
    projectDir: string;
  };
  environment: {
    nodeVersion: string;
    runtimeVersion: string;
    minRequiredMajor: number;
  };
  workspaces: {
    enabled: boolean;
  };
  summary: {
    dependencyCount: number;
    directCount: number;
    transitiveCount: number;
  };
  dependencies: Record<string, DependencyRecord>;
}
