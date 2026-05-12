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

const REGISTRY_FETCH_CONCURRENCY = 3;

const CANDIDATE_REASON_WEIGHTS: Record<string, number> = {
  'supply-chain-source': 5,
  'execution-signals': 5,
  'install-hooks': 4,
  'native-binding': 4,
  'packaging-signals': 3,
  bin: 2
};

/**
 * Compute the difference in days between two Date objects.
 *
 * @param later - The later date to compare
 * @param earlier - The earlier date to compare
 * @returns The difference in days as a number (may be fractional); positive when `later` is after `earlier`, negative when `later` is before `earlier`, and zero when equal
 */
function daysBetween(later: Date, earlier: Date): number {
  return (later.getTime() - earlier.getTime()) / (24 * 60 * 60 * 1000);
}

/**
 * Parse a date string into a JavaScript Date, returning undefined for missing or invalid input.
 *
 * @param value - The date string to parse; may be undefined.
 * @returns A `Date` representing `value` when valid, or `undefined` if `value` is missing or not a valid date.
 */
function parseDate(value: string | undefined): Date | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

/**
 * Determines whether a date string represents a time within the past given number of days relative to `now`.
 *
 * @param value - The date string to evaluate; if `undefined` or unparsable it is treated as not recent.
 * @param now - Reference date to compare against.
 * @param days - Maximum allowed age in days (inclusive).
 * @returns `true` if `value` parses to a date whose age is between 0 and `days` inclusive, `false` otherwise.
 */
function isRecent(value: string | undefined, now: Date, days: number): boolean {
  const date = parseDate(value);
  if (!date) return false;
  const age = daysBetween(now, date);
  return age >= 0 && age <= days;
}

/**
 * Extracts the leading major version number from a semver-like version string.
 *
 * @param version - The version string to parse (e.g., "1.2.3"); may be `undefined`.
 * @returns The major version as an integer if present and numeric, `undefined` otherwise.
 */
function parseMajor(version: string | undefined): number | undefined {
  if (!version) return undefined;
  const match = version.match(/^(\d+)\./);
  if (!match) return undefined;
  const major = Number.parseInt(match[1], 10);
  return Number.isFinite(major) ? major : undefined;
}

/**
 * Produce chronological version entries with parsed publication dates.
 *
 * @param metadata - Parsed npm registry metadata to extract version timestamps from
 * @returns An array of objects for each version that has a parsable timestamp, sorted by ascending publication date. Each object contains `version` (the version string), `date` (the parsed `Date`), and `raw` (the original timestamp string)
 */
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

/**
 * Parse the JSON-like output from `npm view <name> --json` into a normalized registry metadata object.
 *
 * Accepts a raw parsed JSON value and extracts string-valued `time` entries, string-valued `dist-tags`,
 * and a deduplicated, sorted list of `versions`. Returns `undefined` when `raw` is not an object or when
 * none of `time`, `dist-tags`, or `versions` contain usable data.
 *
 * @param name - Package name to set on the returned metadata
 * @param raw - Raw parsed JSON output from `npm view ... --json` (any)
 * @returns A `ParsedNpmMetadata` object containing `name`, `time`, `distTags`, and a deduplicated sorted `versions` array, or `undefined` if parsing yields no usable fields
 */
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

/**
 * Derives conservative registry-based risk signals for a dependency using its installed version and npm registry metadata.
 *
 * @param installedVersion - The package version currently installed to evaluate against registry history
 * @param metadata - Parsed npm registry metadata for the package
 * @param now - Reference time used to evaluate recency thresholds; defaults to the current time
 * @returns An array of detected registry risk signal names in priority order. Possible values:
 * `recent-package`, `recent-version`, `low-release-history`, `reactivated-package`, `old-major-new-patch`
 */
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

/**
 * Extracts package names referenced by supply-chain signals in the aggregated data.
 *
 * @param aggregated - Aggregated data containing `supplyChain.signals`.
 * @returns A set of unique package names. For each signal, `signal.packageName` is used when present; otherwise the name is derived from `signal.packageId` by removing a trailing `@version` segment when present.
 */
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

/**
 * Produce a sorted array of unique suspicious reason identifiers for a dependency.
 *
 * @param dep - Dependency record to evaluate for suspicious attributes
 * @param sourceSignalNames - Set of package names considered supply-chain signal sources
 * @returns An array of unique reason identifiers sorted in ascending order. Possible values include `supply-chain-source`, `install-hooks`, `native-binding`, `bin`, `execution-signals`, and `packaging-signals`
 */
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

/**
 * Selects and ranks package names from an aggregated dependency graph as candidates for npm registry enrichment.
 *
 * The function collects per-dependency suspicious reasons, aggregates them by package name, and returns up to `limit`
 * candidates ordered by total weighted reason score (descending), number of reasons (descending), then package name.
 *
 * @param aggregated - Aggregated dependency graph and supply-chain signals used to derive candidate reasons
 * @param limit - Maximum number of candidates to return; if `limit <= 0` an empty array is returned
 * @returns An array of `RegistryEnrichmentCandidate` objects (each `{ name, reasons }`) where `reasons` is a sorted list of unique reason strings
 */
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
    .sort((a, b) => {
      const score = (reasons: Set<string>) => Array.from(reasons)
        .reduce((total, reason) => total + (CANDIDATE_REASON_WEIGHTS[reason] || 1), 0);
      const scoreDiff = score(b[1]) - score(a[1]);
      if (scoreDiff !== 0) return scoreDiff;
      const reasonCountDiff = b[1].size - a[1].size;
      if (reasonCountDiff !== 0) return reasonCountDiff;
      return a[0].localeCompare(b[0]);
    })
    .slice(0, limit)
    .map(([name, reasons]) => ({ name, reasons: Array.from(reasons).sort() }));
}

/**
 * Fetches and parses npm registry metadata for the given package name using `npm view`.
 *
 * @param name - The package name to query (as passed to `npm view`)
 * @returns A `ToolResult` that is `ok: true` with `data` containing parsed registry metadata on success, or `ok: false` with an `error` message on failure
 */
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

/**
 * Build a DependencyRegistryEnrichment object for a dependency based on an npm registry fetch result.
 *
 * @param dep - The dependency record being enriched
 * @param candidateReasons - The list of suspicious reasons that caused this package to be a candidate
 * @param result - The tool result from fetching parsed npm registry metadata for the package
 * @param now - Reference time used to derive time-based risk signals
 * @returns A DependencyRegistryEnrichment describing the enrichment attempt:
 * - When the fetch failed (`result.ok` is `false` or `result.data` is missing`): `attempted: true`, `ok: false`, `source: 'npm-registry'`, `candidateReasons`, and an `error` message.
 * - When the fetch succeeded: `attempted: true`, `ok: true`, `source: 'npm-registry'`, `candidateReasons`, `versionCount`, and optionally `packageCreatedAt`, `packageModifiedAt`, `installedVersionPublishedAt`, `latestVersion`, `latestPublishedAt`, `distTags`, and `signals` when those values are available.
 */
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

/**
 * Fetches npm registry metadata for the provided candidates in bounded concurrent batches.
 *
 * Processes candidates in batches of size `REGISTRY_FETCH_CONCURRENCY`, invoking `fetcher` for each
 * candidate and collecting results without aborting on individual failures.
 *
 * @param candidates - Candidate packages to fetch registry metadata for.
 * @param fetcher - Function that takes a package name and returns a `ToolResult<ParsedNpmMetadata>`.
 * @returns A map from candidate package name to its `ToolResult<ParsedNpmMetadata>`. If a fetch fails,
 * the corresponding entry will be `{ ok: false, error: <message> }`.
 */
async function fetchRegistryMetadataForCandidates(
  candidates: RegistryEnrichmentCandidate[],
  fetcher: RegistryMetadataFetcher
): Promise<Map<string, ToolResult<ParsedNpmMetadata>>> {
  const results = new Map<string, ToolResult<ParsedNpmMetadata>>();
  for (let index = 0; index < candidates.length; index += REGISTRY_FETCH_CONCURRENCY) {
    const batch = candidates.slice(index, index + REGISTRY_FETCH_CONCURRENCY);
    const settled = await Promise.allSettled(batch.map((candidate) => fetcher(candidate.name)));
    settled.forEach((result, offset) => {
      const name = batch[offset].name;
      results.set(name, result.status === 'fulfilled'
        ? result.value
        : { ok: false, error: result.reason instanceof Error ? result.reason.message : String(result.reason) });
    });
  }
  return results;
}

/**
 * Enriches an aggregated dependency graph with npm registry metadata for selected candidates.
 *
 * @param aggregated - The aggregated dependency data whose dependencies may be enriched.
 * @param options - Optional settings that control enrichment behavior.
 * @param options.offline - When true, skips network activity and returns no candidates.
 * @param options.limit - Maximum number of packages to select for enrichment (defaults to module default).
 * @param options.now - Reference `Date` used for time-based signal derivation (defaults to current time).
 * @param options.fetcher - Optional custom registry fetcher used to retrieve package metadata.
 * @returns An object containing:
 *  - `candidates`: the chosen registry enrichment candidates and their reasons,
 *  - `attempted`: the number of registry lookups attempted,
 *  - `succeeded`: the number of lookups that returned successful metadata results.
 */
export async function enrichAggregatedWithRegistryMetadata(
  aggregated: AggregatedData,
  options: {
    offline?: boolean;
    limit?: number;
    now?: Date;
    fetcher?: RegistryMetadataFetcher;
  } = {}
): Promise<{ candidates: RegistryEnrichmentCandidate[]; attempted: number; succeeded: number }> {
  if (options.offline) return { candidates: [], attempted: 0, succeeded: 0 };
  const candidates = selectRegistryEnrichmentCandidates(
    aggregated,
    options.limit ?? REGISTRY_ENRICHMENT_DEFAULT_LIMIT
  );
  if (candidates.length === 0) return { candidates, attempted: 0, succeeded: 0 };
  const fetcher = options.fetcher || fetchNpmRegistryMetadata;
  const now = options.now || new Date();
  const results = await fetchRegistryMetadataForCandidates(candidates, fetcher);

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

  const succeeded = Array.from(results.values()).filter((result) => result.ok).length;
  return { candidates, attempted: results.size, succeeded };
}
