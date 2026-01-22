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
  status: 'used' | 'unused' | 'unknown';
  reason: string;
}

export interface OutdatedInfo {
  status: 'unknown' | 'available' | 'up-to-date';
  current?: string;
  wanted?: string;
  latest?: string;
}

export interface ImportGraphInfo {
  files: Record<string, string[]>;
  fanIn?: Record<string, number>;
  fanOut?: Record<string, number>;
}

export interface DependencyRecord {
  name: string;
  version: string;
  key: string;
  direct: boolean;
  transitive: boolean;
  depth: number;
  parents: string[];
  license: LicenseInfo;
  licenseRisk: 'green' | 'amber' | 'red';
  vulnerabilities: VulnerabilitySummary;
  vulnRisk: 'green' | 'amber' | 'red';
  maintenance: MaintenanceInfo;
  maintenanceRisk: 'green' | 'amber' | 'red' | 'unknown';
  usage: UsageInfo;
  importInfo?: ImportGraphInfo;
  runtimeClass: 'runtime' | 'build-time' | 'dev-only';
  runtimeReason: string;
  outdated: OutdatedInfo;
  raw?: any;
}

export interface RawOutputs {
  audit?: any;
  npmLs?: any;
  licenseChecker?: any;
  depcheck?: any;
  madge?: any;
}

export interface ToolResult<T> {
  ok: boolean;
  data?: T;
  error?: string;
  file?: string;
}

export interface AggregatedData {
  generatedAt: string;
  projectPath: string;
  maintenanceEnabled: boolean;
  dependencies: DependencyRecord[];
  toolErrors: Record<string, string>;
  raw: RawOutputs;
}

export interface ScanOptions {
  projectPath: string;
  tempDir: string;
  outputPath: string;
  keepTemp?: boolean;
}
