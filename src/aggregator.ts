import {
  AggregatedData,
  DependencyRecord,
  ImportGraphInfo,
  MaintenanceInfo,
  RawOutputs,
  Severity,
  ToolResult,
  UsageInfo,
  VulnerabilitySummary
} from './types';
import {
  licenseRiskLevel,
  maintenanceRisk,
  readPackageJson,
  readLicenseFromPackageJson,
  runCommand,
  delay,
  vulnRiskLevel
} from './utils';

interface AggregateInput {
  projectPath: string;
  maintenanceEnabled: boolean;
  onMaintenanceProgress?: (current: number, total: number, name: string) => void;
  auditResult?: ToolResult<any>;
  npmLsResult?: ToolResult<any>;
  licenseResult?: ToolResult<any>;
  depcheckResult?: ToolResult<any>;
  madgeResult?: ToolResult<any>;
}

interface NodeInfo {
  name: string;
  version: string;
  key: string;
  depth: number;
  parents: Set<string>;
  dev?: boolean;
}

export async function aggregateData(input: AggregateInput): Promise<AggregatedData> {
  const pkg = await readPackageJson(input.projectPath);
  const raw: RawOutputs = {
    audit: input.auditResult?.data,
    npmLs: input.npmLsResult?.data,
    licenseChecker: input.licenseResult?.data,
    depcheck: input.depcheckResult?.data,
    madge: input.madgeResult?.data
  };

  const toolErrors: Record<string, string> = {};
  if (input.auditResult && !input.auditResult.ok) toolErrors['npm-audit'] = input.auditResult.error || 'unknown error';
  if (input.npmLsResult && !input.npmLsResult.ok) toolErrors['npm-ls'] = input.npmLsResult.error || 'unknown error';
  if (input.licenseResult && !input.licenseResult.ok) toolErrors['license-checker'] = input.licenseResult.error || 'unknown error';
  if (input.depcheckResult && !input.depcheckResult.ok) toolErrors['depcheck'] = input.depcheckResult.error || 'unknown error';
  if (input.madgeResult && !input.madgeResult.ok) toolErrors['madge'] = input.madgeResult.error || 'unknown error';

  const nodeMap = buildNodeMap(input.npmLsResult?.data, pkg);
  const vulnMap = parseVulnerabilities(input.auditResult?.data);
  const licenseData = normalizeLicenseData(input.licenseResult?.data);
  const depcheckUsage = buildUsageInfo(input.depcheckResult?.data);
  const importInfo = buildImportInfo(input.madgeResult?.data);
  const maintenanceCache = new Map<string, MaintenanceInfo>();

  const dependencies: DependencyRecord[] = [];
  const licenseFallbackCache = new Map<string, { license?: string; licenseFile?: string }>();

  const nodes = Array.from(nodeMap.values());
  const totalDeps = nodes.length;
  let maintenanceIndex = 0;

  for (const node of nodes) {
    const direct = isDirectDependency(node.name, pkg);
    const license =
      licenseData.byKey.get(node.key) ||
      licenseData.byName.get(node.name) ||
      licenseFallbackCache.get(node.name) ||
      (await readLicenseFromPackageJson(node.name, input.projectPath)) ||
      { license: undefined };
    if (!licenseFallbackCache.has(node.name) && license.license) {
      licenseFallbackCache.set(node.name, license);
    }
    const vulnerabilities = vulnMap.get(node.name) || emptyVulnSummary();
    const licenseRisk = licenseRiskLevel(license.license);
    const vulnRisk = vulnRiskLevel(vulnerabilities.counts);
    const usage = depcheckUsage.get(node.name) ||
      (input.depcheckResult?.data
        ? { status: 'used', reason: 'Not flagged as unused by depcheck' }
        : { status: 'unknown', reason: 'depcheck unavailable' });
    const maintenance = await resolveMaintenance(
      node.name,
      maintenanceCache,
      input.maintenanceEnabled,
      ++maintenanceIndex,
      totalDeps,
      input.onMaintenanceProgress
    );
    if (!maintenanceCache.has(node.name)) {
      maintenanceCache.set(node.name, maintenance);
    }

    const maintenanceRiskLevel = maintenanceRisk(maintenance.lastPublished);
    const runtimeData = classifyRuntime(node, pkg, nodeMap);

    dependencies.push({
      name: node.name,
      version: node.version,
      key: node.key,
      direct,
      transitive: !direct,
      depth: node.depth,
      parents: Array.from(node.parents),
      license,
      licenseRisk,
      vulnerabilities,
      vulnRisk,
      maintenance,
      maintenanceRisk: maintenanceRiskLevel,
      usage,
      importInfo,
      runtimeClass: runtimeData.classification,
      runtimeReason: runtimeData.reason,
      outdated: { status: 'unknown' },
      raw: {}
    });

  }

  dependencies.sort((a, b) => a.name.localeCompare(b.name));

  return {
    generatedAt: new Date().toISOString(),
    projectPath: input.projectPath,
    dependencies,
    toolErrors,
    raw
  };
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
        dev: node.dev
      });
    } else {
      const existing = map.get(key)!;
      existing.depth = Math.min(existing.depth, depth);
      if (parentKey) existing.parents.add(parentKey);
      if (existing.dev === undefined && node.dev !== undefined) existing.dev = node.dev;
    }
    if (node.dependencies && typeof node.dependencies === 'object') {
      Object.entries<any>(node.dependencies).forEach(([depName, child]: [string, any]) => traverse(child, depth + 1, key, depName));
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
      map.set(key, { name, version, key, depth: 1, parents: new Set(), dev: false });
    });
    devDeps.forEach((name) => {
      const version = pkg.devDependencies[name];
      const key = `${name}@${version}`;
      map.set(key, { name, version, key, depth: 1, parents: new Set(), dev: true });
    });
  }

  return map;
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

  if (auditData.vulnerabilities) {
    Object.values<any>(auditData.vulnerabilities).forEach((item: any) => {
      const name = item.name || 'unknown';
      const severity: Severity = normalizeSeverity(item.severity);
      const entry = ensureEntry(name);
      entry.counts[severity] = (entry.counts[severity] || 0) + 1;
      const viaList = Array.isArray(item.via) ? item.via : [];
      viaList
        .filter((v: any) => typeof v === 'object')
        .forEach((vul: any) => {
          const sev: Severity = normalizeSeverity(vul.severity) || severity;
          entry.items.push({
            title: vul.title || item.title || vul.name || name,
            severity: sev,
            url: vul.url,
            vulnerableRange: vul.range,
            fixAvailable: item.fixAvailable,
            paths: item.nodes
          });
          entry.counts[sev] = (entry.counts[sev] || 0) + 0; // already counted above
        });
      entry.highestSeverity = computeHighestSeverity(entry.counts);
    });
  }

  if (auditData.advisories) {
    Object.values<any>(auditData.advisories).forEach((adv: any) => {
      const name = adv.module_name || adv.module || 'unknown';
      const severity: Severity = normalizeSeverity(adv.severity);
      const entry = ensureEntry(name);
      entry.items.push({
        title: adv.title,
        severity,
        url: adv.url,
        vulnerableRange: adv.vulnerable_versions,
        fixAvailable: adv.fix_available,
        paths: (adv.findings || []).flatMap((f: any) => f.paths || [])
      });
      entry.counts[severity] = (entry.counts[severity] || 0) + 1;
      entry.highestSeverity = computeHighestSeverity(entry.counts);
    });
  }

  map.forEach((entry) => {
    entry.highestSeverity = computeHighestSeverity(entry.counts);
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
    items: [],
    highestSeverity: 'none'
  };
}

function computeHighestSeverity(counts: Record<Severity, number>): Severity | 'none' {
  if (counts.critical > 0) return 'critical';
  if (counts.high > 0) return 'high';
  if (counts.moderate > 0) return 'moderate';
  if (counts.low > 0) return 'low';
  return 'none';
}

function normalizeLicenseData(data: any): { byKey: Map<string, { license?: string; licenseFile?: string }>; byName: Map<string, { license?: string; licenseFile?: string }> } {
  const byKey = new Map<string, { license?: string; licenseFile?: string }>();
  const byName = new Map<string, { license?: string; licenseFile?: string }>();
  if (!data) return { byKey, byName };
  Object.entries<any>(data).forEach(([key, value]: [string, any]) => {
    const lic = Array.isArray(value.licenses) ? value.licenses.join(' OR ') : value.licenses;
    const entry = {
      license: lic,
      licenseFile: value.licenseFile || value.licenseFilePath
    };
    byKey.set(key, entry);
    const namePart = key.includes('@', 1) ? key.slice(0, key.lastIndexOf('@')) : key;
    if (!byName.has(namePart)) byName.set(namePart, entry);
  });
  return { byKey, byName };
}

function buildUsageInfo(depcheckData: any): Map<string, UsageInfo> {
  const map = new Map<string, UsageInfo>();
  if (!depcheckData) return map;
  const unused = new Set<string>([...(depcheckData.dependencies || []), ...(depcheckData.devDependencies || [])]);

  unused.forEach((name) => {
    map.set(name, { status: 'unused', reason: 'Marked unused by depcheck' });
  });

  if (Array.isArray(depcheckData.dependencies) || Array.isArray(depcheckData.devDependencies)) {
    Object.keys(depcheckData.missing || {}).forEach((name) => {
      if (!map.has(name)) {
        map.set(name, { status: 'unknown', reason: 'Missing according to depcheck' });
      }
    });
  }

  return map;
}

function buildImportInfo(graphData: any): ImportGraphInfo | undefined {
  if (!graphData || typeof graphData !== 'object') return undefined;
  const fanIn: Record<string, number> = {};
  const fanOut: Record<string, number> = {};
  Object.entries<any>(graphData).forEach(([file, deps]) => {
    fanOut[file] = Array.isArray(deps) ? deps.length : 0;
    (deps || []).forEach((dep: string) => {
      fanIn[dep] = (fanIn[dep] || 0) + 1;
    });
  });
  return { files: graphData, fanIn, fanOut };
}

function isDirectDependency(name: string, pkg: any): boolean {
  return Boolean((pkg.dependencies && pkg.dependencies[name]) || (pkg.devDependencies && pkg.devDependencies[name]));
}

async function resolveMaintenance(
  name: string,
  cache: Map<string, MaintenanceInfo>,
  maintenanceEnabled: boolean,
  current: number,
  total: number,
  onProgress?: (current: number, total: number, name: string) => void
): Promise<MaintenanceInfo> {
  if (cache.has(name)) return cache.get(name)!;
  if (!maintenanceEnabled) {
    return { status: 'unknown', reason: 'maintenance checks disabled' } as MaintenanceInfo;
  }
  onProgress?.(current, total, name);
  try {
    await delay(1000);
    const res = await runCommand('npm', ['view', name, 'time', '--json']);
    const json = JSON.parse(res.stdout || '{}');
    const timestamps = Object.values<string>(json || {}).filter((v) => typeof v === 'string');
    const lastPublished = timestamps.sort().pop();
    if (lastPublished) {
      const risk = maintenanceRisk(lastPublished);
      const status: MaintenanceInfo['status'] = risk === 'green' ? 'active' : risk === 'amber' ? 'quiet' : risk === 'red' ? 'stale' : 'unknown';
      return { lastPublished, status, reason: 'npm view time' };
    }
    return { status: 'unknown', reason: 'npm view returned no data' } as MaintenanceInfo;
  } catch (err: any) {
    return { status: 'unknown', reason: 'lookup failed' } as MaintenanceInfo;
  }
}

function classifyRuntime(node: NodeInfo, pkg: any, map: Map<string, NodeInfo>): { classification: 'runtime' | 'build-time' | 'dev-only'; reason: string } {
  if (pkg.dependencies && pkg.dependencies[node.name]) {
    return { classification: 'runtime', reason: 'Declared in dependencies' };
  }
  if (pkg.devDependencies && pkg.devDependencies[node.name]) {
    return { classification: 'dev-only', reason: 'Declared in devDependencies' };
  }
  if (node.dev) {
    return { classification: 'dev-only', reason: 'npm ls marks as dev dependency' };
  }
  const hasRuntimeParent = Array.from(node.parents).some((parentKey) => {
    const parent = map.get(parentKey);
    return parent ? !parent.dev : false;
  });
  if (hasRuntimeParent) {
    return { classification: 'runtime', reason: 'Transitive of runtime dependency' };
  }
  return { classification: 'build-time', reason: 'Only seen in dev dependency tree' };
}
