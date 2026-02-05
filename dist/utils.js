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
function runCommand(command, args, options = {}) {
    return new Promise((resolve, reject) => {
        const child = (0, child_process_1.spawn)(command, args, {
            cwd: options.cwd,
            shell: false,
            env: options.env ? { ...process.env, ...options.env } : process.env
        });
        const stdoutChunks = [];
        const stderrChunks = [];
        child.stdout.on('data', (d) => stdoutChunks.push(Buffer.from(d)));
        child.stderr.on('data', (d) => stderrChunks.push(Buffer.from(d)));
        child.on('error', (err) => reject(err));
        child.on('close', (code) => {
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
async function writeJsonFile(filePath, data) {
    await ensureDir(path_1.default.dirname(filePath));
    const content = JSON.stringify(data, null, 2);
    await promises_1.default.writeFile(filePath, content, 'utf8');
}
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
        const prefix = entry.split('(')[0];
        if (!prefix)
            continue;
        if (!index.has(prefix))
            index.set(prefix, []);
        index.get(prefix).push(entry);
    }
    pnpmStoreIndexCache.set(pnpmDir, index);
    return index;
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
    let current = startPath;
    while (true) {
        for (const file of lockFiles) {
            if (await pathExists(path_1.default.join(current, file))) {
                return current;
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
