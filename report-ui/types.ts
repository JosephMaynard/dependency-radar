// Client-side types matching src/types.ts
// These are used for the report UI rendering

export type Severity = 'low' | 'moderate' | 'high' | 'critical';

export interface VulnerabilityItem {
  title: string;
  severity: Severity;
  url?: string;
  vulnerableRange?: string;
  fixAvailable?: string | boolean;
  paths?: string[];
}

export interface VulnerabilitySummary {
  counts: Record<Severity, number>;
  items: VulnerabilityItem[];
  highestSeverity: Severity | 'none';
}

export interface LicenseInfo {
  license?: string;
  licenseFile?: string;
}

export interface MaintenanceInfo {
  lastPublished?: string;
  status: 'active' | 'quiet' | 'stale' | 'unknown';
  reason: string;
}

export interface UsageInfo {
  status: 'imported' | 'not-imported' | 'undeclared' | 'unknown';
  reason: string;
}

export interface OutdatedInfo {
  status: 'unknown' | 'available' | 'up-to-date';
  current?: string;
  wanted?: string;
  latest?: string;
}

export interface PackageLinks {
  npm: string;
  repository?: string;
  bugs?: string;
  homepage?: string;
}

export interface IdentityMetadata {
  deprecated: boolean;
  nodeEngine: string | null;
  hasRepository: boolean;
  hasFunding: boolean;
}

export interface DependencySurface {
  dependencies: number;
  devDependencies: number;
  peerDependencies: number;
  optionalDependencies: number;
  hasPeerDependencies: boolean;
}

export interface SizeFootprint {
  installedSize: number;
  fileCount: number;
}

export interface BuildPlatformInfo {
  nativeBindings: boolean;
  installScripts: boolean;
}

export interface ModuleSystemInfo {
  format: 'commonjs' | 'esm' | 'dual' | 'unknown';
  conditionalExports: boolean;
}

export interface TypeSupportInfo {
  types: 'none' | 'bundled';
}

export interface GraphShape {
  fanIn: number;
  fanOut: number;
  dependedOnBy: string[];
  dependsOn: string[];
}

export interface DependencyRecord {
  name: string;
  version: string;
  key: string;
  direct: boolean;
  transitive: boolean;
  depth: number;
  parents: string[];
  rootCauses: string[];
  license: LicenseInfo;
  licenseRisk: 'green' | 'amber' | 'red';
  vulnerabilities: VulnerabilitySummary;
  vulnRisk: 'green' | 'amber' | 'red';
  maintenance: MaintenanceInfo;
  maintenanceRisk: 'green' | 'amber' | 'red' | 'unknown';
  usage: UsageInfo;
  identity: IdentityMetadata;
  dependencySurface: DependencySurface;
  sizeFootprint: SizeFootprint;
  buildPlatform: BuildPlatformInfo;
  moduleSystem: ModuleSystemInfo;
  typescript: TypeSupportInfo;
  graph: GraphShape;
  links: PackageLinks;
  runtimeClass: 'runtime' | 'build-time' | 'dev-only';
  runtimeReason: string;
  outdated: OutdatedInfo;
}

export interface NodeEnvironmentInfo {
  runtimeVersion: string;
  runtimeMajor: number;
  minRequiredMajor?: number;
  source: 'dependency-engines' | 'project-engines' | 'unknown';
}

export interface EnvironmentInfo {
  node: NodeEnvironmentInfo;
}

export interface AggregatedData {
  generatedAt: string;
  projectPath: string;
  gitBranch?: string;
  dependencyRadarVersion?: string;
  maintenanceEnabled: boolean;
  environment: EnvironmentInfo;
  dependencies: DependencyRecord[];
  toolErrors: Record<string, string>;
}
