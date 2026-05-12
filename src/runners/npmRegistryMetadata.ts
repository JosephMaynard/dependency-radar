import type {
  AggregatedData,
  DependencyRecord,
  DependencyRegistryEnrichment,
  RegistryRiskSignal,
  ToolResult
} from '../types';
import { parseJsonOutput, runCommand } from '../utils';

export const REGISTRY_ENRICHMENT_DEFAULT_LIMIT = 10;

// Thresholds are intentionally conservative and easy to explain in README/report output.
const RECENT_PACKAGE_DAYS = 14;
const RECENT_VERSION_DAYS = 14;
const LOW_RELEASE_HISTORY_VERSION_COUNT = 3;
const REACTIVATED_RECENT_DAYS = 30;
const REACTIVATED_DORMANT_DAYS = 365;
const OLD_MAJOR_PATCH_RECENT_DAYS = 30;

export interface RegistryEnrichmentCandidate {
  name: string;
  reasons: string[];
}

export interface ParsedNpmMetadata {
  name: string;
  time: Record<string, string>;
  distTags: Record<string, string>;
  versions: string[];
}

type RegistryMetadataFetcher = (name: string) => Promise<ToolResult<ParsedNpmMetadata>>;

function daysBetween(later: Date, earlier: Date): number {
  return (later.getTime() - earlier.getTime()) / (24 * 60 * 60 * 1000);
}

function parseDate(value: string | undefined): Date | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

function isRecent(value: string | undefined, now: Date, days: number): boolean {
  const date = parseDate(value);
  if (!date) return false;
  const age = daysBetween(now, date);
  return age >= 0 && age <= days;
}

function parseMajor(version: string | undefined): number | undefined {
  if (!version) return undefined;
  const match = version.match(/^(\d+)\./);
  if (!match) return undefined;
  const major = Number.parseInt(match[1], 10);
  return Number.isFinite(major) ? major : undefined;
}

function versionTimeEntries(metadata: ParsedNpmMetadata): Array<{ version: string; date: Date; raw: string }> {
  return metadata.versions
    .map((version) => {
      const raw = metadata.time[version];
      const date = parseDate(raw);
      return date ? { version, date, raw } : undefined;
    })
    .filter((entry): entry is { version: string; date: Date; raw: string } => Boolean(entry))
    .sort((a, b) => a.date.getTime() - b.date.getTime());
}

export function parseNpmRegistryMetadata(name: string, raw: unknown): ParsedNpmMetadata | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const data = raw as Record<string, any>;
  const time = data.time && typeof data.time === 'object' && !Array.isArray(data.time)
    ? Object.fromEntries(
        Object.entries(data.time)
          .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
      )
    : {};
  const distTags = data['dist-tags'] && typeof data['dist-tags'] === 'object' && !Array.isArray(data['dist-tags'])
    ? Object.fromEntries(
        Object.entries(data['dist-tags'])
          .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
      )
    : {};
  const versions = Array.isArray(data.versions)
    ? data.versions.filter((version): version is string => typeof version === 'string' && version.trim().length > 0)
    : Object.keys(data.versions || {}).filter(Boolean);
  if (Object.keys(time).length === 0 && versions.length === 0 && Object.keys(distTags).length === 0) {
    return undefined;
  }
  return {
    name,
    time,
    distTags,
    versions: Array.from(new Set(versions)).sort()
  };
}

export function deriveRegistryRiskSignals(
  installedVersion: string,
  metadata: ParsedNpmMetadata,
  now = new Date()
): RegistryRiskSignal[] {
  const signals = new Set<RegistryRiskSignal>();
  const installedPublishedAt = metadata.time[installedVersion];
  if (isRecent(metadata.time.created, now, RECENT_PACKAGE_DAYS)) {
    signals.add('recent-package');
  }
  if (isRecent(installedPublishedAt, now, RECENT_VERSION_DAYS)) {
    signals.add('recent-version');
  }
  if (metadata.versions.length > 0 && metadata.versions.length <= LOW_RELEASE_HISTORY_VERSION_COUNT) {
    signals.add('low-release-history');
  }

  const entries = versionTimeEntries(metadata);
  const latest = entries[entries.length - 1];
  const previous = entries[entries.length - 2];
  if (
    latest &&
    previous &&
    isRecent(latest.raw, now, REACTIVATED_RECENT_DAYS) &&
    daysBetween(latest.date, previous.date) >= REACTIVATED_DORMANT_DAYS
  ) {
    signals.add('reactivated-package');
  }

  const installedMajor = parseMajor(installedVersion);
  const latestVersion = metadata.distTags.latest;
  const latestMajor = parseMajor(latestVersion);
  if (
    installedMajor !== undefined &&
    latestMajor !== undefined &&
    installedMajor < latestMajor &&
    isRecent(installedPublishedAt, now, OLD_MAJOR_PATCH_RECENT_DAYS)
  ) {
    signals.add('old-major-new-patch');
  }

  return [
    'recent-package',
    'recent-version',
    'low-release-history',
    'reactivated-package',
    'old-major-new-patch'
  ].filter((signal): signal is RegistryRiskSignal => signals.has(signal as RegistryRiskSignal));
}

function supplyChainSignalPackageNames(aggregated: AggregatedData): Set<string> {
  const names = new Set<string>();
  for (const signal of aggregated.supplyChain?.signals || []) {
    if (signal.packageName) {
      names.add(signal.packageName);
      continue;
    }
    if (signal.packageId) {
      const at = signal.packageId.lastIndexOf('@');
      if (at > 0) names.add(signal.packageId.slice(0, at));
    }
  }
  return names;
}

function suspiciousReasons(dep: DependencyRecord, sourceSignalNames: Set<string>): string[] {
  const reasons: string[] = [];
  if (sourceSignalNames.has(dep.package.name)) reasons.push('supply-chain-source');
  if (dep.execution?.scripts?.hooks?.length) reasons.push('install-hooks');
  if (dep.execution?.native) reasons.push('native-binding');
  if (dep.package.hasBin) reasons.push('bin');
  if (dep.execution?.signals?.length || dep.execution?.scripts?.signals?.length) reasons.push('execution-signals');
  if (dep.packaging?.signals?.length) reasons.push('packaging-signals');
  return Array.from(new Set(reasons)).sort();
}

export function selectRegistryEnrichmentCandidates(
  aggregated: AggregatedData,
  limit = REGISTRY_ENRICHMENT_DEFAULT_LIMIT
): RegistryEnrichmentCandidate[] {
  if (limit <= 0) return [];
  const sourceSignalNames = supplyChainSignalPackageNames(aggregated);
  const byName = new Map<string, Set<string>>();
  for (const dep of Object.values(aggregated.dependencies || {})) {
    const reasons = suspiciousReasons(dep, sourceSignalNames);
    if (reasons.length === 0) continue;
    const existing = byName.get(dep.package.name) || new Set<string>();
    reasons.forEach((reason) => existing.add(reason));
    byName.set(dep.package.name, existing);
  }
  return Array.from(byName.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([name, reasons]) => ({ name, reasons: Array.from(reasons).sort() }));
}

export async function fetchNpmRegistryMetadata(name: string): Promise<ToolResult<ParsedNpmMetadata>> {
  try {
    const result = await runCommand('npm', ['view', name, '--json', 'time', 'dist-tags', 'versions'], {
      timeoutMs: 30_000,
      maxOutputBytes: 2 * 1024 * 1024
    });
    if (result.code !== 0) {
      return { ok: false, error: result.stderr || result.stdout || `npm view exited with code ${result.code}` };
    }
    const parsed = parseJsonOutput(result.stdout);
    const metadata = parseNpmRegistryMetadata(name, parsed);
    if (!metadata) {
      return { ok: false, error: 'npm registry metadata was unavailable or incomplete' };
    }
    return { ok: true, data: metadata };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

function buildRegistryEnrichment(
  dep: DependencyRecord,
  candidateReasons: string[],
  result: ToolResult<ParsedNpmMetadata>,
  now: Date
): DependencyRegistryEnrichment {
  if (!result.ok || !result.data) {
    return {
      attempted: true,
      ok: false,
      source: 'npm-registry',
      candidateReasons,
      error: result.error || 'npm registry metadata lookup failed'
    };
  }
  const metadata = result.data;
  const signals = deriveRegistryRiskSignals(dep.package.version, metadata, now);
  const latestVersion = metadata.distTags.latest;
  const latestPublishedAt = latestVersion ? metadata.time[latestVersion] : undefined;
  return {
    attempted: true,
    ok: true,
    source: 'npm-registry',
    candidateReasons,
    ...(metadata.time.created ? { packageCreatedAt: metadata.time.created } : {}),
    ...(metadata.time.modified ? { packageModifiedAt: metadata.time.modified } : {}),
    ...(metadata.time[dep.package.version] ? { installedVersionPublishedAt: metadata.time[dep.package.version] } : {}),
    ...(latestVersion ? { latestVersion } : {}),
    ...(latestPublishedAt ? { latestPublishedAt } : {}),
    versionCount: metadata.versions.length,
    ...(Object.keys(metadata.distTags).length > 0 ? { distTags: metadata.distTags } : {}),
    ...(signals.length > 0 ? { signals } : {})
  };
}

export async function enrichAggregatedWithRegistryMetadata(
  aggregated: AggregatedData,
  options: {
    offline?: boolean;
    limit?: number;
    now?: Date;
    fetcher?: RegistryMetadataFetcher;
  } = {}
): Promise<{ candidates: RegistryEnrichmentCandidate[]; attempted: number }> {
  if (options.offline) return { candidates: [], attempted: 0 };
  const candidates = selectRegistryEnrichmentCandidates(
    aggregated,
    options.limit ?? REGISTRY_ENRICHMENT_DEFAULT_LIMIT
  );
  if (candidates.length === 0) return { candidates, attempted: 0 };
  const fetcher = options.fetcher || fetchNpmRegistryMetadata;
  const now = options.now || new Date();
  const results = new Map<string, ToolResult<ParsedNpmMetadata>>();

  for (const candidate of candidates) {
    results.set(candidate.name, await fetcher(candidate.name));
  }

  const reasonsByName = new Map(candidates.map((candidate) => [candidate.name, candidate.reasons]));
  for (const dep of Object.values(aggregated.dependencies || {})) {
    const result = results.get(dep.package.name);
    if (!result) continue;
    const candidateReasons = reasonsByName.get(dep.package.name) || [];
    dep.supplyChain = {
      ...(dep.supplyChain || {}),
      registry: buildRegistryEnrichment(dep, candidateReasons, result, now)
    };
  }

  return { candidates, attempted: results.size };
}
