import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { ensureDir, readJsonFile } from './utils';

export interface MaintenanceCacheEntry {
  fetchedAt: string;
  modified?: string;
  latestVersion?: string;
  // Only versions with a truthy `deprecated` field, message capped for size.
  deprecatedVersions?: Record<string, string>;
  latestDeprecated?: true;
  repo?: {
    checkedAt: string;
    archived: boolean;
  };
}

interface MaintenanceCacheFile {
  version: 1;
  entries: Record<string, MaintenanceCacheEntry>;
}

export const MAINTENANCE_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const CACHE_FILE_VERSION = 1;
const CACHE_FILE_NAME = 'registry-maintenance-v1.json';
const MAX_CACHE_ENTRIES = 5_000;

/**
 * Resolve the cache directory for registry maintenance data.
 *
 * Order: DEPENDENCY_RADAR_CACHE_DIR env override, XDG_CACHE_HOME, the
 * platform-local cache root (%LOCALAPPDATA% on Windows), then ~/.cache.
 * Returns undefined when DEPENDENCY_RADAR_NO_CACHE=1 disables caching.
 */
export function resolveMaintenanceCacheDir(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (env.DEPENDENCY_RADAR_NO_CACHE === '1') return undefined;
  if (env.DEPENDENCY_RADAR_CACHE_DIR) {
    return path.join(env.DEPENDENCY_RADAR_CACHE_DIR, 'dependency-radar');
  }
  if (env.XDG_CACHE_HOME) {
    return path.join(env.XDG_CACHE_HOME, 'dependency-radar');
  }
  if (process.platform === 'win32' && env.LOCALAPPDATA) {
    return path.join(env.LOCALAPPDATA, 'dependency-radar');
  }
  return path.join(os.homedir(), '.cache', 'dependency-radar');
}

/**
 * Best-effort persistent cache for registry maintenance lookups.
 *
 * Failure-tolerant by design: unreadable, corrupt, or version-mismatched
 * cache files are treated as empty, and persistence failures are swallowed.
 * Writes go through a temp file + rename in the same directory so concurrent
 * scans can only race whole files (last writer wins), never tear one.
 */
export class MaintenanceCache {
  // Null-prototype store: package names are untrusted (they come from
  // installed package.json files), and a name like "__proto__" must behave
  // as a plain key rather than mutating the object's prototype.
  private entries: Record<string, MaintenanceCacheEntry> = Object.create(null);
  private readonly filePath?: string;
  private readonly ttlMs: number;

  constructor(cacheDir?: string, ttlMs: number = MAINTENANCE_CACHE_TTL_MS) {
    this.filePath = cacheDir ? path.join(cacheDir, CACHE_FILE_NAME) : undefined;
    this.ttlMs = ttlMs;
  }

  /** Load the cache snapshot from disk; any failure yields an empty cache. */
  async load(): Promise<void> {
    if (!this.filePath) return;
    try {
      const parsed = await readJsonFile<MaintenanceCacheFile>(this.filePath);
      if (parsed && parsed.version === CACHE_FILE_VERSION && parsed.entries && typeof parsed.entries === 'object') {
        this.entries = Object.assign(Object.create(null), parsed.entries);
      }
    } catch {
      this.entries = Object.create(null);
    }
  }

  /** Return the fresh (within TTL) entry for a package name, if any. */
  getFresh(name: string, now: Date = new Date()): MaintenanceCacheEntry | undefined {
    const entry = this.entries[name];
    if (!entry || !entry.fetchedAt) return undefined;
    const fetchedAt = Date.parse(entry.fetchedAt);
    if (Number.isNaN(fetchedAt) || now.getTime() - fetchedAt > this.ttlMs) return undefined;
    return entry;
  }

  /** Merge a fresh lookup result into the in-memory snapshot. */
  set(name: string, entry: MaintenanceCacheEntry): void {
    this.entries[name] = entry;
  }

  /** Record a repo-archived check on an existing (or new) entry. */
  setRepoCheck(name: string, archived: boolean, now: Date = new Date()): void {
    const existing = this.entries[name] || { fetchedAt: now.toISOString() };
    existing.repo = { checkedAt: now.toISOString(), archived };
    this.entries[name] = existing;
  }

  /**
   * Persist the snapshot to disk (temp file + rename, last writer wins).
   * Prunes oldest entries beyond the cap. Never throws.
   */
  async save(): Promise<void> {
    if (!this.filePath) return;
    try {
      const names = Object.keys(this.entries);
      if (names.length > MAX_CACHE_ENTRIES) {
        names
          .sort((a, b) => Date.parse(this.entries[a]?.fetchedAt || '') - Date.parse(this.entries[b]?.fetchedAt || ''))
          .slice(0, names.length - MAX_CACHE_ENTRIES)
          .forEach((name) => {
            delete this.entries[name];
          });
      }
      const payload: MaintenanceCacheFile = { version: CACHE_FILE_VERSION, entries: this.entries };
      const dir = path.dirname(this.filePath);
      await ensureDir(dir);
      const tempPath = path.join(dir, `.${CACHE_FILE_NAME}.${process.pid}.tmp`);
      await fs.writeFile(tempPath, JSON.stringify(payload), 'utf8');
      await fs.rename(tempPath, this.filePath);
    } catch {
      // Cache persistence is best-effort; scans never fail because of it.
    }
  }
}
