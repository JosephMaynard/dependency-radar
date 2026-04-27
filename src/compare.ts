import type { AggregatedData, DependencyFinding, DependencyRecord } from './types';

export interface CompareResult {
  added: string[];
  removed: string[];
  newFindings: DependencyFinding[];
  resolvedFindings: DependencyFinding[];
  changedFindings: DependencyFinding[];
  changedVersions: Array<{ name: string; from: string; to: string }>;
}

function byName(deps: Record<string, DependencyRecord>): Map<string, DependencyRecord[]> {
  const map = new Map<string, DependencyRecord[]>();
  for (const dep of Object.values(deps || {})) {
    if (!map.has(dep.package.name)) map.set(dep.package.name, []);
    map.get(dep.package.name)!.push(dep);
  }
  return map;
}

export function compareReports(previous: AggregatedData, current: AggregatedData): CompareResult {
  const previousIds = new Set(Object.keys(previous.dependencies || {}));
  const currentIds = new Set(Object.keys(current.dependencies || {}));
  const added = Array.from(currentIds).filter((id) => !previousIds.has(id)).sort();
  const removed = Array.from(previousIds).filter((id) => !currentIds.has(id)).sort();

  const previousByName = byName(previous.dependencies || {});
  const currentByName = byName(current.dependencies || {});
  const changedVersions: CompareResult['changedVersions'] = [];
  for (const [name, previousDeps] of previousByName.entries()) {
    const currentDeps = currentByName.get(name);
    if (!currentDeps || currentDeps.length !== 1 || previousDeps.length !== 1) continue;
    const prev = previousDeps[0];
    const next = currentDeps[0];
    if (prev.package.version !== next.package.version) {
      changedVersions.push({ name, from: prev.package.version, to: next.package.version });
    }
  }
  changedVersions.sort((a, b) => a.name.localeCompare(b.name));

  const previousFindingIds = new Set((previous.findings || []).map((finding) => finding.id));
  const currentFindingIds = new Set((current.findings || []).map((finding) => finding.id));
  const byFindingId = (a: DependencyFinding, b: DependencyFinding) => (a.id || '').localeCompare(b.id || '');
  const previousFindingById = new Map((previous.findings || []).map((finding) => [finding.id, finding]));
  const serializeFinding = (finding: DependencyFinding): string => JSON.stringify({
    category: finding.category,
    severity: finding.severity,
    packageId: finding.packageId,
    packageName: finding.packageName,
    packageVersion: finding.packageVersion,
    title: finding.title,
    message: finding.message,
    evidence: finding.evidence,
    recommendation: finding.recommendation
  });
  return {
    added,
    removed,
    changedVersions,
    newFindings: (current.findings || []).filter((finding) => !previousFindingIds.has(finding.id)).sort(byFindingId),
    resolvedFindings: (previous.findings || []).filter((finding) => !currentFindingIds.has(finding.id)).sort(byFindingId),
    changedFindings: (current.findings || [])
      .filter((finding) => {
        const previousFinding = previousFindingById.get(finding.id);
        return previousFinding ? serializeFinding(previousFinding) !== serializeFinding(finding) : false;
      })
      .sort(byFindingId)
  };
}

function section(title: string, lines: string[], empty: string): string[] {
  return [
    title,
    '-'.repeat(title.length),
    ...(lines.length > 0 ? lines : [empty]),
    ''
  ];
}

export function formatCompareOutput(result: CompareResult): string {
  const lines: string[] = ['Dependency Radar comparison', '===========================', ''];
  lines.push(...section('Added dependencies', result.added.map((id) => `+ ${id}`), 'none'));
  lines.push(...section('Removed dependencies', result.removed.map((id) => `- ${id}`), 'none'));
  lines.push(...section(
    'Changed versions',
    result.changedVersions.map((entry) => `${entry.name}: ${entry.from} -> ${entry.to}`),
    'none'
  ));
  lines.push(...section(
    'New findings',
    result.newFindings.map((finding) => `${finding.severity.toUpperCase()} ${finding.packageId}: ${finding.title}`),
    'none'
  ));
  lines.push(...section(
    'Changed findings',
    result.changedFindings.map((finding) => `${finding.severity.toUpperCase()} ${finding.packageId}: ${finding.title}`),
    'none'
  ));
  lines.push(...section(
    'Resolved findings',
    result.resolvedFindings.map((finding) => `${finding.packageId}: ${finding.title}`),
    'none'
  ));
  return lines.join('\n').trimEnd();
}
