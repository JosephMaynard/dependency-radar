// Client-side types matching src/types.ts
// These are used for the report UI rendering

export type Severity = 'low' | 'moderate' | 'high' | 'critical';
export type OutdatedStatus = 'current' | 'patch' | 'minor' | 'major' | 'unknown';

export interface DependencyObject {
  id: string;
  name: string;
  version: string;
  direct: boolean;
  scope: 'runtime' | 'dev' | 'optional' | 'peer';
  depth: number;
  origins: {
    workspaces?: string[];
    rootPackageCount: number;
    topRootPackages: string[];
  };
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
  build: {
    native: boolean;
    installScripts: boolean;
    risk: 'green' | 'amber' | 'red';
  };
  tsTypes: 'bundled' | 'definitelyTyped' | 'none' | 'unknown';
  dependencySurface: {
    deps: number;
    dev: number;
    peer: number;
    opt: number;
  };
  graph: {
    fanIn: number;
    fanOut: number;
  };
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

export interface AggregatedData {
  schemaVersion: '1.0';
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
  dependencies: Record<string, DependencyObject>;
}
