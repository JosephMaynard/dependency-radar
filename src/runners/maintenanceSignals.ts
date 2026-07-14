import https from 'https';
import {
  AggregatedData,
  DependencyMaintenanceInfo,
  DependencyRecord,
  MaintenanceStatus
} from '../types';
import { HttpJsonResult, httpGetJson, mapWithConcurrency } from '../httpClient';
import {
  MAINTENANCE_CACHE_TTL_MS,
  MaintenanceCache,
  MaintenanceCacheEntry,
  resolveMaintenanceCacheDir
} from '../maintenanceCache';
import { runCommand } from '../utils';

// This runner complements src/runners/npmRegistryMetadata.ts rather than
// replacing it: that module shells out to `npm view` for a small set of
// suspicious packages (inheriting npm auth/proxy handling), while this one
// does broad, unauthenticated, cache-backed lookups against the public
// registry metadata surface for maintenance signals.

export const DEFAULT_MAINTENANCE_BUDGET_MS = 20_000;
export const DEFAULT_MAINTENANCE_NAME_LIMIT = 1_500;
const PACKUMENT_CONCURRENCY = 8;
const PACKUMENT_TIMEOUT_MS = 10_000;
const ARCHIVED_CHECK_CAP = 50;
const ARCHIVED_CHECK_CONCURRENCY = 4;
const ARCHIVED_CHECK_TIMEOUT_MS = 8_000;
const ARCHIVED_PHASE_BUDGET_MS = 10_000;
const ARCHIVED_BREAKER_FAILURES = 3;
const DEFAULT_REGISTRY_URL = 'https://registry.npmjs.org';
const ECOSYSTEMS_REPOS_BASE = 'https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories';

// `modified` updates on ANY packument write, so these age thresholds strictly
// under-flag: a package past them has had zero registry writes of any kind.
const STALE_MONTHS = 18;
const UNMAINTAINED_MONTHS = 36;
const ARCHIVED_CANDIDATE_MONTHS = 24;
const MS_PER_MONTH = 30.44 * 24 * 60 * 60 * 1000;

const DEPRECATION_MESSAGE_MAX_LENGTH = 300;
const DEPRECATED_VERSIONS_CAP = 500;

export type PackumentFetcher = (name: string) => Promise<HttpJsonResult>;
export type RepoArchivedFetcher = (owner: string, repo: string) => Promise<HttpJsonResult>;

export interface MaintenanceEnrichmentOptions {
  offline?: boolean;
  now?: Date;
  projectPath?: string;
  registryUrl?: string;
  fetcher?: PackumentFetcher;
  repoFetcher?: RepoArchivedFetcher;
  cache?: MaintenanceCache;
  budgetMs?: number;
  limit?: number;
}

export interface MaintenanceEnrichmentSummary {
  checkedNames: number;
  attempted: number;
  succeeded: number;
  fromCache: number;
  truncatedNames: number;
  deprecatedNames: number;
  archivedNames: number;
  unmaintainedNames: number;
}

interface NameLookup {
  entry?: MaintenanceCacheEntry;
  fromCache?: boolean;
  error?: string;
}

function emptySummary(): MaintenanceEnrichmentSummary {
  return {
    checkedNames: 0,
    attempted: 0,
    succeeded: 0,
    fromCache: 0,
    truncatedNames: 0,
    deprecatedNames: 0,
    archivedNames: 0,
    unmaintainedNames: 0
  };
}

/** Encode a package name for use as a single registry URL path segment. */
function encodePackageName(name: string): string {
  // Names come from installed package.json files (untrusted content), so
  // percent-encode every segment; the scope separator becomes %2F.
  return name.split('/').map(encodeURIComponent).join('%2F');
}

/**
 * Resolve the default registry base URL via `npm config get registry` so
 * project/user .npmrc overrides are respected. Falls back to the public
 * registry on any failure. Per-scope registries are intentionally not
 * resolved and no auth is ever attached.
 */
export async function resolveRegistryBaseUrl(projectPath?: string, timeoutMs = 10_000): Promise<string> {
  if (timeoutMs <= 0) return DEFAULT_REGISTRY_URL;
  try {
    const result = await runCommand('npm', ['config', 'get', 'registry'], {
      cwd: projectPath,
      timeoutMs
    });
    const url = result.stdout?.trim();
    if (url && /^https?:\/\//i.test(url)) {
      const parsed = new URL(url);
      parsed.username = '';
      parsed.password = '';
      return parsed.toString().replace(/\/+$/, '');
    }
  } catch {
    // fall through to the default
  }
  return DEFAULT_REGISTRY_URL;
}

function remainingBudgetMs(deadline: number): number {
  return Math.max(0, deadline - Date.now());
}

function timeoutWithinBudget(deadline: number, maxTimeoutMs: number): number {
  return Math.min(maxTimeoutMs, remainingBudgetMs(deadline));
}

function deadlineWithPhaseCap(deadline: number, maxPhaseMs: number): number {
  const now = Date.now();
  const remainingMs = Math.max(0, deadline - now);
  return Math.min(deadline, now + Math.min(maxPhaseMs, remainingMs));
}

/**
 * Extract the maintenance-relevant subset of an abbreviated packument
 * (`Accept: application/vnd.npm.install-v1+json`) into a compact cache entry.
 *
 * @returns The cache entry, or undefined when the payload has no usable shape.
 */
export function parseAbbreviatedPackument(data: unknown, now: Date): MaintenanceCacheEntry | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const packument = data as Record<string, any>;
  const versions = packument.versions;
  const distTags = packument['dist-tags'];
  if ((!versions || typeof versions !== 'object') && (!distTags || typeof distTags !== 'object')) {
    return undefined;
  }

  // Cap every string persisted to the cache: the registry response is
  // untrusted input and must not be able to bloat the cache file.
  const entry: MaintenanceCacheEntry = { fetchedAt: now.toISOString() };
  if (typeof packument.modified === 'string') entry.modified = packument.modified.slice(0, 64);
  const latest = distTags && typeof distTags.latest === 'string' ? distTags.latest : undefined;
  if (latest) entry.latestVersion = latest.slice(0, 64);

  if (versions && typeof versions === 'object') {
    const deprecatedVersions: Record<string, string> = {};
    let count = 0;
    for (const [version, meta] of Object.entries<any>(versions)) {
      if (!meta || typeof meta !== 'object') continue;
      if (version.length > 256) continue;
      const deprecated = meta.deprecated;
      // npm treats any non-empty string (and boolean true) as deprecated.
      if (deprecated === undefined || deprecated === false || deprecated === '') continue;
      if (count >= DEPRECATED_VERSIONS_CAP) break;
      deprecatedVersions[version] = typeof deprecated === 'string'
        ? deprecated.slice(0, DEPRECATION_MESSAGE_MAX_LENGTH)
        : 'deprecated';
      count += 1;
    }
    if (count > 0) entry.deprecatedVersions = deprecatedVersions;
    if (latest && deprecatedVersions[latest] !== undefined) entry.latestDeprecated = true;
  }

  return entry;
}

/** Floor of whole months between a timestamp and `now`; undefined when unparseable or in the future. */
function monthsSince(timestamp: string | undefined, now: Date): number | undefined {
  if (!timestamp) return undefined;
  const then = Date.parse(timestamp);
  if (Number.isNaN(then)) return undefined;
  const diff = now.getTime() - then;
  if (diff < 0) return 0;
  return Math.floor(diff / MS_PER_MONTH);
}

/**
 * Derive the maintenance status from observed facts, first match wins:
 * deprecated → archived → unmaintained (36+ months without any registry
 * write) → stale (18+ months) → active.
 */
export function deriveMaintenanceStatus(facts: {
  deprecated: boolean;
  repoArchived?: boolean;
  monthsSinceModified?: number;
}): MaintenanceStatus {
  if (facts.deprecated) return 'deprecated';
  if (facts.repoArchived === true) return 'archived';
  if (facts.monthsSinceModified !== undefined) {
    if (facts.monthsSinceModified >= UNMAINTAINED_MONTHS) return 'unmaintained';
    if (facts.monthsSinceModified >= STALE_MONTHS) return 'stale';
  }
  return 'active';
}

/**
 * Parse a GitHub repository URL in its common package.json forms
 * (https, git+https, git, ssh, scp-like, with .git/#fragment//tree suffixes)
 * into an owner/repo pair. Returns undefined for anything that is not
 * unambiguously a GitHub repository.
 */
export function parseGitHubRepo(url: string | undefined): { owner: string; repo: string } | undefined {
  if (!url || typeof url !== 'string') return undefined;
  let normalized = url.trim();
  const scpMatch = normalized.match(/^git@github\.com:(.+)$/i);
  if (scpMatch) normalized = `https://github.com/${scpMatch[1]}`;
  normalized = normalized.replace(/^git\+/, '');
  normalized = normalized.replace(/^(git|ssh):\/\//i, 'https://');
  normalized = normalized.replace(/^https:\/\/git@/i, 'https://');
  const match = normalized.match(/^https?:\/\/(?:www\.)?github\.com\/([^/#?]+)\/([^/#?]+)/i);
  if (!match) return undefined;
  const owner = match[1];
  const repo = match[2].replace(/\.git$/i, '');
  if (!owner || !repo) return undefined;
  return { owner, repo };
}

interface ArchivedCheckCandidate {
  name: string;
  owner: string;
  repo: string;
  priority: number;
}

/**
 * Select the bounded set of packages worth a repo-archived lookup:
 * registry-deprecated packages first, then direct dependencies, then
 * packages with no registry writes for 24+ months — each requiring a
 * parseable GitHub repository URL.
 */
export function selectArchivedCheckCandidates(
  byName: Map<string, DependencyRecord[]>,
  lookupByName: Map<string, NameLookup>,
  now: Date,
  cap = ARCHIVED_CHECK_CAP
): ArchivedCheckCandidate[] {
  const candidates: ArchivedCheckCandidate[] = [];
  for (const [name, records] of byName) {
    const lookup = lookupByName.get(name);
    const entry = lookup?.entry;
    if (!entry) continue;
    if (entry.repo && isRepoCheckFresh(entry, now)) continue;

    const deprecated = Boolean(
      entry.latestDeprecated ||
      (entry.deprecatedVersions &&
        records.some((dep) => entry.deprecatedVersions![dep.package.version] !== undefined))
    );
    const direct = records.some((dep) => dep.usage.direct);
    const months = monthsSince(entry.modified, now);
    const dormant = months !== undefined && months >= ARCHIVED_CANDIDATE_MONTHS;

    let priority: number | undefined;
    if (deprecated) priority = 0;
    else if (direct) priority = 1;
    else if (dormant) priority = 2;
    if (priority === undefined) continue;

    const repoUrl = records
      .map((dep) => dep.package.links.repository)
      .find((candidate) => parseGitHubRepo(candidate));
    const parsed = parseGitHubRepo(repoUrl);
    if (!parsed) continue;

    candidates.push({ name, owner: parsed.owner, repo: parsed.repo, priority });
  }
  return candidates
    .sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name))
    .slice(0, cap);
}

function isRepoCheckFresh(entry: MaintenanceCacheEntry, now: Date): boolean {
  if (!entry.repo?.checkedAt) return false;
  const checkedAt = Date.parse(entry.repo.checkedAt);
  if (Number.isNaN(checkedAt)) return false;
  return now.getTime() - checkedAt <= MAINTENANCE_CACHE_TTL_MS;
}

function buildMaintenanceInfo(
  dep: DependencyRecord,
  lookup: NameLookup,
  now: Date
): DependencyMaintenanceInfo {
  const entry = lookup.entry;
  if (!entry) {
    return {
      attempted: true,
      ok: false,
      status: 'unknown',
      error: lookup.error || 'registry lookup failed'
    };
  }

  const installedDeprecated = Boolean(
    entry.deprecatedVersions && entry.deprecatedVersions[dep.package.version] !== undefined
  );
  const latestDeprecated = entry.latestDeprecated === true;
  const message = entry.deprecatedVersions
    ? entry.deprecatedVersions[dep.package.version] ??
      (entry.latestVersion ? entry.deprecatedVersions[entry.latestVersion] : undefined)
    : undefined;
  const months = monthsSince(entry.modified, now);

  const info: DependencyMaintenanceInfo = {
    attempted: true,
    ok: true,
    status: deriveMaintenanceStatus({
      deprecated: installedDeprecated || latestDeprecated,
      repoArchived: entry.repo?.archived,
      monthsSinceModified: months
    }),
    fetchedAt: entry.fetchedAt
  };
  if (installedDeprecated || latestDeprecated) {
    info.deprecated = {
      installedVersion: installedDeprecated,
      latestVersion: latestDeprecated
    };
    if (message && message !== 'deprecated') info.deprecated.message = message;
  }
  if (entry.repo) {
    info.repoArchived = entry.repo.archived;
    info.repoCheckedAt = entry.repo.checkedAt;
  }
  if (entry.modified) info.packageModifiedAt = entry.modified;
  if (months !== undefined) info.monthsSinceModified = months;
  if (entry.latestVersion) info.latestVersion = entry.latestVersion;
  if (lookup.fromCache) info.fromCache = true;
  return info;
}

/**
 * Enrich aggregated dependencies with registry maintenance signals.
 *
 * Fetches abbreviated packuments for (up to `limit`) unique package names,
 * runs bounded best-effort repo-archived checks, derives per-dependency
 * maintenance statuses, and mutates the aggregated records in place:
 * `dep.maintenance`, `dep.package.deprecated` + the `deprecated` upgrade
 * blocker (when registry-deprecated), and `dep.upgrade.latestVersion`
 * backfill. Never throws; every failure degrades to `status: 'unknown'`.
 */
export async function enrichAggregatedWithMaintenanceSignals(
  aggregated: AggregatedData,
  options: MaintenanceEnrichmentOptions = {}
): Promise<MaintenanceEnrichmentSummary> {
  const summary = emptySummary();
  if (options.offline) return summary;
  const deps = Object.values(aggregated.dependencies || {});
  if (deps.length === 0) return summary;

  const now = options.now || new Date();
  const byName = new Map<string, DependencyRecord[]>();
  for (const dep of deps) {
    const list = byName.get(dep.package.name) || [];
    list.push(dep);
    byName.set(dep.package.name, list);
  }

  const maxFanIn = (records: DependencyRecord[]) =>
    records.reduce((max, dep) => Math.max(max, dep.graph.fanIn || 0), 0);
  const hasDirect = (records: DependencyRecord[]) => records.some((dep) => dep.usage.direct);
  const names = Array.from(byName.keys()).sort((a, b) => {
    const directDiff = Number(hasDirect(byName.get(b)!)) - Number(hasDirect(byName.get(a)!));
    if (directDiff !== 0) return directDiff;
    const fanInDiff = maxFanIn(byName.get(b)!) - maxFanIn(byName.get(a)!);
    if (fanInDiff !== 0) return fanInDiff;
    return a.localeCompare(b);
  });

  const limit = options.limit ?? DEFAULT_MAINTENANCE_NAME_LIMIT;
  const targetNames = names.slice(0, Math.max(0, limit));
  summary.checkedNames = targetNames.length;
  summary.truncatedNames = names.length - targetNames.length;

  const budgetMs = options.budgetMs ?? DEFAULT_MAINTENANCE_BUDGET_MS;
  const deadline = Date.now() + budgetMs;
  const cache = options.cache || new MaintenanceCache(resolveMaintenanceCacheDir());
  await cache.load();

  const agent = new https.Agent({ keepAlive: true, maxSockets: PACKUMENT_CONCURRENCY });
  try {
    let fetcher = options.fetcher;
    if (!fetcher) {
      const registry =
        options.registryUrl ||
        (await resolveRegistryBaseUrl(options.projectPath, timeoutWithinBudget(deadline, 10_000)));
      // The keep-alive agent is https-only; an http registry (e.g. a private
      // mirror) must not receive it or Node rejects the request outright.
      const registryAgent = registry.toLowerCase().startsWith('https:') ? agent : undefined;
      fetcher = (name: string) => {
        const timeoutMs = timeoutWithinBudget(deadline, PACKUMENT_TIMEOUT_MS);
        if (timeoutMs <= 0) {
          return Promise.resolve({ ok: false, error: 'maintenance time budget exhausted' });
        }
        return httpGetJson(`${registry}/${encodePackageName(name)}`, {
          headers: { Accept: 'application/vnd.npm.install-v1+json' },
          timeoutMs,
          agent: registryAgent
        });
      };
    }

    const lookupByName = new Map<string, NameLookup>();

    const lookups = await mapWithConcurrency(
      targetNames,
      PACKUMENT_CONCURRENCY,
      deadline,
      async (name): Promise<NameLookup & { name: string }> => {
        const cached = cache.getFresh(name, now);
        if (cached) {
          return { name, entry: cached, fromCache: true };
        }
        const result = await fetcher!(name);
        if (!result.ok || result.data === undefined) {
          return { name, error: result.error || 'registry lookup failed' };
        }
        const entry = parseAbbreviatedPackument(result.data, now);
        if (!entry) {
          return { name, error: 'unrecognized registry response' };
        }
        cache.set(name, entry);
        return { name, entry, fromCache: false };
      },
      (name) => ({ name, error: 'maintenance time budget exhausted' })
    );

    for (const lookup of lookups) {
      if (!lookup) continue;
      lookupByName.set(lookup.name, lookup);
      if (lookup.entry && lookup.fromCache) summary.fromCache += 1;
      if (lookup.entry && lookup.fromCache === false) {
        summary.attempted += 1;
        summary.succeeded += 1;
      }
      if (!lookup.entry && lookup.error !== 'maintenance time budget exhausted') summary.attempted += 1;
    }

    // Bounded best-effort repo-archived checks with a circuit breaker.
    const candidates = selectArchivedCheckCandidates(byName, lookupByName, now);
    if (candidates.length > 0) {
      const repoFetcher: RepoArchivedFetcher =
        options.repoFetcher ||
        ((owner: string, repo: string) => {
          const timeoutMs = timeoutWithinBudget(deadline, ARCHIVED_CHECK_TIMEOUT_MS);
          if (timeoutMs <= 0) {
            return Promise.resolve({ ok: false, error: 'maintenance time budget exhausted' });
          }
          return httpGetJson(
            `${ECOSYSTEMS_REPOS_BASE}/${encodeURIComponent(owner)}%2F${encodeURIComponent(repo)}`,
            { timeoutMs, agent }
          );
        });
      let breakerTripped = false;
      let consecutiveFailures = 0;
      const archivedDeadline = deadlineWithPhaseCap(deadline, ARCHIVED_PHASE_BUDGET_MS);
      await mapWithConcurrency(candidates, ARCHIVED_CHECK_CONCURRENCY, archivedDeadline, async (candidate) => {
        if (breakerTripped) return undefined;
        const result = await repoFetcher(candidate.owner, candidate.repo);
        if (result.status === 429) {
          breakerTripped = true;
          return undefined;
        }
        if (!result.ok || !result.data || typeof (result.data as any).archived !== 'boolean') {
          consecutiveFailures += 1;
          if (consecutiveFailures >= ARCHIVED_BREAKER_FAILURES) breakerTripped = true;
          return undefined;
        }
        consecutiveFailures = 0;
        const archived = Boolean((result.data as any).archived);
        cache.setRepoCheck(candidate.name, archived, now);
        const lookup = lookupByName.get(candidate.name);
        if (lookup?.entry) {
          lookup.entry.repo = { checkedAt: now.toISOString(), archived };
        }
        return undefined;
      });
    }

    // Apply results to every record and promote registry deprecation into
    // the existing package/blocker surfaces.
    for (const [name, records] of byName) {
      const lookup = lookupByName.get(name);
      if (!lookup) continue; // beyond the name cap — leave records untouched
      let nameDeprecated = false;
      let nameArchived = false;
      let nameUnmaintained = false;
      for (const dep of records) {
        const info = buildMaintenanceInfo(dep, lookup, now);
        dep.maintenance = info;
        if (info.status === 'deprecated') {
          nameDeprecated = true;
          dep.package.deprecated = true;
          const blockers = dep.upgrade.blockers || [];
          if (!blockers.includes('deprecated')) blockers.push('deprecated');
          dep.upgrade.blockers = blockers;
        }
        if (info.status === 'archived') nameArchived = true;
        if (info.status === 'unmaintained') nameUnmaintained = true;
        if (info.latestVersion && !dep.upgrade.latestVersion) {
          dep.upgrade.latestVersion = info.latestVersion;
        }
      }
      if (nameDeprecated) summary.deprecatedNames += 1;
      if (nameArchived) summary.archivedNames += 1;
      if (nameUnmaintained) summary.unmaintainedNames += 1;
    }

    await cache.save();
  } finally {
    agent.destroy();
  }

  return summary;
}
