export type Severity = 'low' | 'moderate' | 'high' | 'critical';
export type OutdatedStatus = 'current' | 'patch' | 'minor' | 'major' | 'unknown';

export interface VulnerabilitySummary {
  counts: Record<Severity, number>;
  highestSeverity: Severity | 'none';
}

export interface DependencySurface {
  deps: number;
  dev: number;
  peer: number;
  opt: number;
}

export interface DependencyOrigins {
  rootPackageCount: number;
  topRootPackages: string[];
  workspaces?: string[];
}

export interface DependencyBuildInfo {
  native: boolean;
  installScripts: boolean;
  risk: 'green' | 'amber' | 'red';
}

export interface DependencyGraphSummary {
  fanIn: number;
  fanOut: number;
}

export interface DependencyObject {
  id: string;
  name: string;
  version: string;
  direct: boolean;
  scope: 'runtime' | 'dev' | 'optional' | 'peer';
  depth: number;
  origins: DependencyOrigins;
  license: string;
  licenseRisk: 'green' | 'amber' | 'red';
  vulnerabilities: {
    critical: number;
    high: number;
    moderate: number;
    low: number;
    highest: Severity | 'none';
  };
  vulnRisk: 'green' | 'amber' | 'red';
  deprecated: boolean;
  nodeEngine: string | null;
  build: DependencyBuildInfo;
  tsTypes: 'bundled' | 'definitelyTyped' | 'none' | 'unknown';
  dependencySurface: DependencySurface;
  graph: DependencyGraphSummary;
  links: {
    npm: string;
  };
  usage?: {
    fileCount: number;
    topFiles: string[];
  };
  introduction?: 'direct' | 'tooling' | 'framework' | 'testing' | 'transitive' | 'unknown';
  runtimeImpact?: 'runtime' | 'build' | 'testing' | 'tooling' | 'mixed';
  upgrade?: {
    blocksNodeMajor: boolean;
    blockers: Array<'nodeEngine' | 'peerDependency' | 'nativeBindings' | 'deprecated'>;
  };
  outdated?: {
    status: OutdatedStatus;
    latestVersion?: string;
  };
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

export interface AggregatedData {
  schemaVersion: '1.0';
  generatedAt: string;
  dependencyRadarVersion: string;
  git: {
    branch: string;
  };
  project: {
    projectDir: string;
    projectPathHash: string;
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
  dependencies: Record<string, DependencyObject>;
}

export interface ScanOptions {
  projectPath: string;
  tempDir: string;
  outputPath: string;
  keepTemp?: boolean;
}
