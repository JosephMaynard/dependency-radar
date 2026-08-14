"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runCommand = runCommand;
exports.getDependencyRadarVersion = getDependencyRadarVersion;
exports.ensureDir = ensureDir;
exports.writeJsonFile = writeJsonFile;
exports.pathExists = pathExists;
exports.removeDir = removeDir;
exports.readJsonFile = readJsonFile;
exports.readPackageJson = readPackageJson;
exports.findBin = findBin;
exports.licenseRiskLevel = licenseRiskLevel;
exports.vulnRiskLevel = vulnRiskLevel;
exports.resolvePackageJsonPath = resolvePackageJsonPath;
exports.readLicenseFromPackageJson = readLicenseFromPackageJson;
exports.readLicenseFromPackageDir = readLicenseFromPackageDir;
exports.findLockDir = findLockDir;
exports.parseJsonOutput = parseJsonOutput;
const child_process_1 = require("child_process");
const fs_1 = __importDefault(require("fs"));
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const workspaceGlobs_1 = require("./workspaceGlobs");
function runCommand(command, args, options = {}) {
    return new Promise((resolve, reject) => {
        var _a;
        const validPositive = (value, fallback) => {
            const parsed = typeof value === 'number' ? value : Number(value);
            return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
        };
        const timeoutMs = validPositive((_a = options.timeoutMs) !== null && _a !== void 0 ? _a : process.env.DEPENDENCY_RADAR_COMMAND_TIMEOUT_MS, 120000);
        const maxOutputBytes = validPositive(options.maxOutputBytes, 50 * 1024 * 1024);
        const child = (0, child_process_1.spawn)(command, args, {
            cwd: options.cwd,
            shell: false,
            env: options.env ? { ...process.env, ...options.env } : process.env
        });
        const stdoutChunks = [];
        const stderrChunks = [];
        let totalBytes = 0;
        let settled = false;
        let timedOut = false;
        let outputExceeded = false;
        function terminate() {
            var _a, _b;
            child.kill('SIGTERM');
            (_b = (_a = setTimeout(() => {
                if (!settled)
                    child.kill('SIGKILL');
            }, 2000)).unref) === null || _b === void 0 ? void 0 : _b.call(_a);
        }
        const timer = timeoutMs > 0
            ? setTimeout(() => {
                timedOut = true;
                terminate();
            }, timeoutMs)
            : undefined;
        function collect(chunks, data) {
            const nextBytes = totalBytes + data.length;
            if (nextBytes > maxOutputBytes) {
                outputExceeded = true;
                const remaining = Math.max(0, maxOutputBytes - totalBytes);
                if (remaining > 0)
                    chunks.push(Buffer.from(data.subarray(0, remaining)));
                totalBytes = maxOutputBytes;
                terminate();
                return;
            }
            chunks.push(Buffer.from(data));
            totalBytes = nextBytes;
        }
        child.stdout.on('data', (d) => {
            collect(stdoutChunks, Buffer.from(d));
        });
        child.stderr.on('data', (d) => {
            collect(stderrChunks, Buffer.from(d));
        });
        child.on('error', (err) => {
            if (timer)
                clearTimeout(timer);
            settled = true;
            reject(err);
        });
        child.on('close', (code) => {
            if (timer)
                clearTimeout(timer);
            settled = true;
            if (timedOut) {
                reject(new Error(`${command} timed out after ${timeoutMs}ms`));
                return;
            }
            if (outputExceeded) {
                reject(new Error(`${command} output exceeded ${maxOutputBytes} bytes`));
                return;
            }
            resolve({
                stdout: Buffer.concat(stdoutChunks).toString('utf8'),
                stderr: Buffer.concat(stderrChunks).toString('utf8'),
                code
            });
        });
    });
}
function getDependencyRadarVersion() {
    try {
        const pkgPath = path_1.default.join(__dirname, '..', 'package.json');
        const raw = fs_1.default.readFileSync(pkgPath, 'utf8');
        const pkg = JSON.parse(raw);
        return pkg.version || 'unknown';
    }
    catch {
        return 'unknown';
    }
}
async function ensureDir(dir) {
    await promises_1.default.mkdir(dir, { recursive: true });
}
/**
 * Write JSON data to a file, creating parent directories as needed.
 *
 * Attempts to write a pretty-printed JSON representation of `data` to `filePath`. If pretty-printing fails due to an "Invalid string length" RangeError, falls back to a compact JSON representation.
 *
 * @param filePath - The path of the file to write
 * @param data - The value to serialize to JSON (typically JSON-serializable)
 * @throws Rethrows errors from JSON serialization (except handled "Invalid string length" for pretty-printing) and filesystem write operations
 */
async function writeJsonFile(filePath, data) {
    await ensureDir(path_1.default.dirname(filePath));
    let content;
    try {
        content = JSON.stringify(data, null, 2);
    }
    catch (err) {
        // Large lockfile-derived trees can overflow string length when pretty-printing.
        if (!isInvalidStringLengthError(err))
            throw err;
        content = JSON.stringify(data);
    }
    await promises_1.default.writeFile(filePath, content, 'utf8');
}
/**
 * Determines whether a value is a RangeError whose message indicates an "Invalid string length".
 *
 * @param error - The value to inspect
 * @returns `true` if `error` is a `RangeError` with a message matching "Invalid string length" (case-insensitive), `false` otherwise.
 */
function isInvalidStringLengthError(error) {
    if (!(error instanceof RangeError))
        return false;
    return /Invalid string length/i.test(error.message || '');
}
/**
 * Check whether a filesystem path exists and is accessible.
 *
 * @param target - The path to check
 * @returns `true` if the path exists and is accessible, `false` otherwise
 */
async function pathExists(target) {
    try {
        await promises_1.default.access(target);
        return true;
    }
    catch (err) {
        return false;
    }
}
async function removeDir(target) {
    await promises_1.default.rm(target, { recursive: true, force: true });
}
async function readJsonFile(filePath) {
    const raw = await promises_1.default.readFile(filePath, 'utf8');
    return JSON.parse(raw);
}
async function readPackageJson(projectPath) {
    const pkgPath = path_1.default.join(projectPath, 'package.json');
    const pkgRaw = await promises_1.default.readFile(pkgPath, 'utf8');
    return JSON.parse(pkgRaw);
}
function findBin(projectPath, binName) {
    const ext = process.platform === 'win32' ? '.cmd' : '';
    const candidates = [
        path_1.default.join(projectPath, 'node_modules', '.bin', `${binName}${ext}`),
        path_1.default.join(process.cwd(), 'node_modules', '.bin', `${binName}${ext}`),
        path_1.default.join(__dirname, '..', 'node_modules', '.bin', `${binName}${ext}`),
        `${binName}${ext}`
    ];
    for (const candidate of candidates) {
        if (fs_1.default.existsSync(candidate))
            return candidate;
    }
    return candidates[candidates.length - 1];
}
function licenseRiskLevel(license) {
    if (!license)
        return 'red';
    const normalized = license.toUpperCase();
    const green = ['MIT', 'BSD-2-CLAUSE', 'BSD-3-CLAUSE', 'APACHE-2.0', 'ISC'];
    const amber = ['LGPL', 'LGPL-2.1', 'LGPL-3.0', 'MPL', 'MPL-2.0'];
    if (green.includes(normalized))
        return 'green';
    if (amber.includes(normalized))
        return 'amber';
    return 'red';
}
function vulnRiskLevel(counts) {
    const { low = 0, moderate = 0, high = 0, critical = 0 } = counts;
    if (high > 0 || critical > 0)
        return 'red';
    if (low > 0 || moderate > 0)
        return 'amber';
    return 'green';
}
const pnpmStoreEntriesCache = new Map();
const pnpmStoreIndexCache = new Map();
function encodePnpmStoreName(pkgName) {
    if (pkgName.startsWith('@')) {
        const parts = pkgName.slice(1).split('/');
        if (parts.length >= 2) {
            return `@${parts[0]}+${parts.slice(1).join('+')}`;
        }
    }
    return pkgName.replace(/\//g, '+');
}
async function getPnpmStoreEntries(pnpmDir) {
    if (pnpmStoreEntriesCache.has(pnpmDir))
        return pnpmStoreEntriesCache.get(pnpmDir);
    try {
        const entries = await promises_1.default.readdir(pnpmDir, { withFileTypes: true });
        const dirs = entries.filter((e) => e.isDirectory()).map((e) => e.name);
        pnpmStoreEntriesCache.set(pnpmDir, dirs);
        return dirs;
    }
    catch {
        pnpmStoreEntriesCache.set(pnpmDir, []);
        return [];
    }
}
async function getPnpmStoreIndex(pnpmDir) {
    if (pnpmStoreIndexCache.has(pnpmDir))
        return pnpmStoreIndexCache.get(pnpmDir);
    const entries = await getPnpmStoreEntries(pnpmDir);
    const index = new Map();
    for (const entry of entries) {
        const prefix = extractPnpmStoreEntryPrefix(entry);
        if (!prefix)
            continue;
        if (!index.has(prefix))
            index.set(prefix, []);
        index.get(prefix).push(entry);
    }
    pnpmStoreIndexCache.set(pnpmDir, index);
    return index;
}
function extractPnpmStoreEntryPrefix(entry) {
    const atIndex = entry.startsWith('@') ? entry.indexOf('@', 1) : entry.indexOf('@');
    if (atIndex <= 0)
        return entry.split('(')[0];
    const versionAndSuffix = entry.slice(atIndex + 1);
    const underscoreIndex = versionAndSuffix.indexOf('_');
    const parenIndex = versionAndSuffix.indexOf('(');
    let cutoff = versionAndSuffix.length;
    if (underscoreIndex >= 0)
        cutoff = Math.min(cutoff, underscoreIndex);
    if (parenIndex >= 0)
        cutoff = Math.min(cutoff, parenIndex);
    return entry.slice(0, atIndex + 1 + cutoff);
}
async function resolvePnpmPackageJsonPath(pkgName, version, resolvePaths) {
    if (!version || version.startsWith('link:') || version.startsWith('workspace:') || version.startsWith('file:')) {
        return undefined;
    }
    const encoded = encodePnpmStoreName(pkgName);
    const prefix = `${encoded}@${version}`;
    for (const basePath of resolvePaths) {
        const pnpmDir = path_1.default.join(basePath, 'node_modules', '.pnpm');
        if (!(await pathExists(pnpmDir)))
            continue;
        const index = await getPnpmStoreIndex(pnpmDir);
        const matches = index.get(prefix) || [];
        for (const entry of matches) {
            const candidate = path_1.default.join(pnpmDir, entry, 'node_modules', pkgName, 'package.json');
            if (await pathExists(candidate))
                return candidate;
        }
    }
    return undefined;
}
async function resolvePackageJsonPath(pkgName, resolvePaths, version) {
    if (version) {
        const pnpmResolved = await resolvePnpmPackageJsonPath(pkgName, version, resolvePaths);
        if (pnpmResolved)
            return pnpmResolved;
    }
    try {
        const direct = require.resolve(path_1.default.join(pkgName, 'package.json'), { paths: resolvePaths });
        if (direct)
            return direct;
    }
    catch {
        // fall through to entry resolution
    }
    let entryPath;
    try {
        entryPath = require.resolve(pkgName, { paths: resolvePaths });
    }
    catch {
        return undefined;
    }
    let current = path_1.default.dirname(entryPath);
    const root = path_1.default.parse(current).root;
    while (true) {
        const candidate = path_1.default.join(current, 'package.json');
        if (await pathExists(candidate))
            return candidate;
        const parent = path_1.default.dirname(current);
        if (parent === current || parent === root)
            break;
        current = parent;
    }
    return undefined;
}
async function readLicenseFromPackageJson(pkgName, resolvePaths, version) {
    try {
        const pkgJsonPath = await resolvePackageJsonPath(pkgName, resolvePaths, version);
        if (!pkgJsonPath)
            return undefined;
        return await readLicenseFromPackageDir(path_1.default.dirname(pkgJsonPath));
    }
    catch (err) {
        return undefined;
    }
}
async function readLicenseFromPackageDir(packageDir) {
    try {
        const pkgPath = path_1.default.join(packageDir, 'package.json');
        const pkgRaw = await promises_1.default.readFile(pkgPath, 'utf8');
        const pkg = JSON.parse(pkgRaw);
        const license = pkg.license || (Array.isArray(pkg.licenses) ? pkg.licenses.map((l) => (typeof l === 'string' ? l : l === null || l === void 0 ? void 0 : l.type)).filter(Boolean).join(' OR ') : undefined);
        const licenseFile = await findLicenseFile(packageDir);
        if (!license && !licenseFile)
            return undefined;
        let licenseText;
        if (licenseFile) {
            try {
                licenseText = await promises_1.default.readFile(licenseFile, 'utf8');
            }
            catch {
                licenseText = undefined;
            }
        }
        return { license, licenseFile, licenseText };
    }
    catch {
        return undefined;
    }
}
async function findLicenseFile(dir) {
    try {
        const entries = await promises_1.default.readdir(dir, { withFileTypes: true });
        const fileNames = entries.filter((e) => e.isFile()).map((e) => e.name);
        const patterns = [/^licen[cs]e(\.|$)/, /^copying(\.|$)/, /^notice(\.|$)/];
        const match = fileNames.find((name) => {
            const lower = name.toLowerCase();
            return patterns.some((pattern) => pattern.test(lower));
        });
        return match ? path_1.default.join(dir, match) : undefined;
    }
    catch {
        return undefined;
    }
}
async function findLockDir(startPath, lockFiles) {
    let current = path_1.default.resolve(startPath);
    const resolvedStart = current;
    while (true) {
        for (const file of lockFiles) {
            if (await pathExists(path_1.default.join(current, file))) {
                // The project's own lockfile always applies. An ancestor's lockfile
                // only applies when that ancestor is a workspace root whose declared
                // patterns actually select the scanned path — a truthy `workspaces`
                // field alone is not membership, and an unrelated project's lockfile
                // would report evidence for the wrong dependency tree.
                if (current === resolvedStart)
                    return current;
                const patterns = await (0, workspaceGlobs_1.readWorkspacePatterns)(current);
                if (patterns && patterns.length > 0) {
                    const rel = path_1.default
                        .relative(current, resolvedStart)
                        .split(path_1.default.sep)
                        .join('/');
                    if ((0, workspaceGlobs_1.matchesWorkspacePatterns)(patterns, rel))
                        return current;
                }
                return undefined;
            }
        }
        const parent = path_1.default.dirname(current);
        if (parent === current)
            break;
        current = parent;
    }
    return undefined;
}
function parseJsonOutput(raw) {
    if (!raw)
        return undefined;
    try {
        return JSON.parse(raw);
    }
    catch {
        const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
        const parsed = [];
        for (const line of lines) {
            try {
                parsed.push(JSON.parse(line));
            }
            catch {
                // ignore non-JSON lines
            }
        }
        return parsed.length > 0 ? parsed : undefined;
    }
}
