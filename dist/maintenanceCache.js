"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MaintenanceCache = exports.MAINTENANCE_CACHE_TTL_MS = void 0;
exports.resolveMaintenanceCacheDir = resolveMaintenanceCacheDir;
const promises_1 = __importDefault(require("fs/promises"));
const os_1 = __importDefault(require("os"));
const path_1 = __importDefault(require("path"));
const utils_1 = require("./utils");
exports.MAINTENANCE_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const CACHE_FILE_VERSION = 1;
const CACHE_FILE_NAME = 'registry-maintenance-v1.json';
const MAX_CACHE_ENTRIES = 5000;
/**
 * Resolve the cache directory for registry maintenance data.
 *
 * Order: DEPENDENCY_RADAR_CACHE_DIR env override, XDG_CACHE_HOME, the
 * platform-local cache root (%LOCALAPPDATA% on Windows), then ~/.cache.
 * Returns undefined when DEPENDENCY_RADAR_NO_CACHE=1 disables caching.
 */
function resolveMaintenanceCacheDir(env = process.env) {
    if (env.DEPENDENCY_RADAR_NO_CACHE === '1')
        return undefined;
    if (env.DEPENDENCY_RADAR_CACHE_DIR) {
        return path_1.default.join(env.DEPENDENCY_RADAR_CACHE_DIR, 'dependency-radar');
    }
    if (env.XDG_CACHE_HOME) {
        return path_1.default.join(env.XDG_CACHE_HOME, 'dependency-radar');
    }
    if (process.platform === 'win32' && env.LOCALAPPDATA) {
        return path_1.default.join(env.LOCALAPPDATA, 'dependency-radar');
    }
    return path_1.default.join(os_1.default.homedir(), '.cache', 'dependency-radar');
}
/**
 * Best-effort persistent cache for registry maintenance lookups.
 *
 * Failure-tolerant by design: unreadable, corrupt, or version-mismatched
 * cache files are treated as empty, and persistence failures are swallowed.
 * Writes go through a temp file + rename in the same directory so concurrent
 * scans can only race whole files (last writer wins), never tear one.
 */
class MaintenanceCache {
    constructor(cacheDir, ttlMs = exports.MAINTENANCE_CACHE_TTL_MS) {
        // Null-prototype store: package names are untrusted (they come from
        // installed package.json files), and a name like "__proto__" must behave
        // as a plain key rather than mutating the object's prototype.
        this.entries = Object.create(null);
        this.filePath = cacheDir ? path_1.default.join(cacheDir, CACHE_FILE_NAME) : undefined;
        this.ttlMs = ttlMs;
    }
    /** Load the cache snapshot from disk; any failure yields an empty cache. */
    async load() {
        if (!this.filePath)
            return;
        try {
            const parsed = await (0, utils_1.readJsonFile)(this.filePath);
            if (parsed && parsed.version === CACHE_FILE_VERSION && parsed.entries && typeof parsed.entries === 'object') {
                this.entries = Object.assign(Object.create(null), parsed.entries);
            }
        }
        catch {
            this.entries = Object.create(null);
        }
    }
    /** Return the fresh (within TTL) entry for a package name, if any. */
    getFresh(name, now = new Date()) {
        const entry = this.entries[name];
        if (!entry || !entry.fetchedAt)
            return undefined;
        const fetchedAt = Date.parse(entry.fetchedAt);
        if (Number.isNaN(fetchedAt) || now.getTime() - fetchedAt > this.ttlMs)
            return undefined;
        return entry;
    }
    /** Merge a fresh lookup result into the in-memory snapshot. */
    set(name, entry) {
        this.entries[name] = entry;
    }
    /** Record a repo-archived check on an existing (or new) entry. */
    setRepoCheck(name, archived, now = new Date(), pushedAt) {
        const existing = this.entries[name] || { fetchedAt: now.toISOString() };
        existing.repo = { checkedAt: now.toISOString(), archived, ...(pushedAt ? { pushedAt } : {}) };
        this.entries[name] = existing;
    }
    /**
     * Persist the snapshot to disk (temp file + rename, last writer wins).
     * Prunes oldest entries beyond the cap. Never throws.
     */
    async save() {
        if (!this.filePath)
            return;
        try {
            const names = Object.keys(this.entries);
            if (names.length > MAX_CACHE_ENTRIES) {
                names
                    .sort((a, b) => { var _a, _b; return Date.parse(((_a = this.entries[a]) === null || _a === void 0 ? void 0 : _a.fetchedAt) || '') - Date.parse(((_b = this.entries[b]) === null || _b === void 0 ? void 0 : _b.fetchedAt) || ''); })
                    .slice(0, names.length - MAX_CACHE_ENTRIES)
                    .forEach((name) => {
                    delete this.entries[name];
                });
            }
            const payload = { version: CACHE_FILE_VERSION, entries: this.entries };
            const dir = path_1.default.dirname(this.filePath);
            await (0, utils_1.ensureDir)(dir);
            const tempPath = path_1.default.join(dir, `.${CACHE_FILE_NAME}.${process.pid}.tmp`);
            await promises_1.default.writeFile(tempPath, JSON.stringify(payload), 'utf8');
            await promises_1.default.rename(tempPath, this.filePath);
        }
        catch {
            // Cache persistence is best-effort; scans never fail because of it.
        }
    }
}
exports.MaintenanceCache = MaintenanceCache;
