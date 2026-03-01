"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runNpmLs = runNpmLs;
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const utils_1 = require("../utils");
const lockfileGraph_1 = require("./lockfileGraph");
const PNPM_DEPTH_ATTEMPTS = ['Infinity', '8', '4', '2', '1'];
const PNPM_MAX_OLD_SPACE_SIZE_MB = '8192';
/**
 * Produce a unified dependency tree for a project by using a lockfile if available or by running the package manager's list command and normalizing its output.
 *
 * @param projectPath - Path to the project whose dependencies should be listed
 * @param tempDir - Directory where the resulting JSON file and any diagnostics will be written
 * @param tool - Package manager to use (`npm`, `pnpm`, or `yarn`)
 * @param options - Optional progress callbacks and context; if `lockfileSearchRoot` is provided it will be used as the root when searching for a lockfile
 * @returns The tool result. On success, `data` is the normalized dependency tree and `file` is the path of the written JSON; on failure, `error` contains a message suitable for users and `file` points to the diagnostics JSON written to disk.
 */
async function runNpmLs(projectPath, tempDir, tool = 'npm', options = {}) {
    const persistToDisk = options.persistToDisk !== false;
    const targetFile = path_1.default.join(tempDir, `${tool}-ls.json`);
    try {
        const lockfileTree = await (0, lockfileGraph_1.tryBuildDependencyTreeFromLockfile)(projectPath, tool, options.lockfileSearchRoot);
        if (lockfileTree) {
            if (persistToDisk) {
                await (0, utils_1.writeJsonFile)(targetFile, lockfileTree.data);
            }
            return { ok: true, data: lockfileTree.data, ...(persistToDisk ? { file: targetFile } : {}) };
        }
        if (tool === 'pnpm') {
            return await runPnpmLsWithFallback(projectPath, targetFile, options);
        }
        const { args, normalize } = buildLsCommand(tool);
        const result = await (0, utils_1.runCommand)(tool, args, { cwd: projectPath });
        const parsed = parseJsonOutput(result.stdout);
        const normalized = normalize(parsed);
        if (normalized) {
            if (persistToDisk) {
                await (0, utils_1.writeJsonFile)(targetFile, normalized);
            }
            return { ok: true, data: normalized, ...(persistToDisk ? { file: targetFile } : {}) };
        }
        if (persistToDisk) {
            await (0, utils_1.writeJsonFile)(targetFile, { stdout: result.stdout, stderr: result.stderr, code: result.code });
        }
        const error = buildLsFailureMessage(tool, result.code, result.stderr);
        return { ok: false, error, ...(persistToDisk ? { file: targetFile } : {}) };
    }
    catch (err) {
        if (persistToDisk) {
            await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        }
        return {
            ok: false,
            error: `${tool} ls failed: ${String(err)}`,
            ...(persistToDisk ? { file: targetFile } : {})
        };
    }
}
function buildLsCommand(tool) {
    if (tool === 'yarn') {
        return {
            args: ['list', '--json', '--depth', 'Infinity'],
            normalize: normalizeYarnTree
        };
    }
    return {
        args: ['ls', '--json', '--all', '--long'],
        normalize: normalizeNpmTree
    };
}
async function runPnpmLsWithFallback(projectPath, targetFile, options) {
    const persistToDisk = options.persistToDisk !== false;
    const installState = createPnpmInstallState(projectPath);
    const attempts = [];
    const env = {
        NODE_OPTIONS: ensureNodeMaxOldSpaceSize(process.env.NODE_OPTIONS, PNPM_MAX_OLD_SPACE_SIZE_MB)
    };
    for (let index = 0; index < PNPM_DEPTH_ATTEMPTS.length; index++) {
        const depth = PNPM_DEPTH_ATTEMPTS[index];
        const result = await (0, utils_1.runCommand)('pnpm', ['list', '--json', '--depth', depth], {
            cwd: projectPath,
            env
        });
        const parsed = parseJsonOutput(result.stdout);
        const normalized = normalizePnpmTree(parsed, installState);
        const outOfMemory = isOutOfMemoryError(result.stderr);
        attempts.push({
            depth,
            code: result.code,
            stdoutBytes: Buffer.byteLength(result.stdout || '', 'utf8'),
            stderrPreview: trimText(result.stderr, 1200),
            outOfMemory
        });
        if (normalized) {
            if (index > 0) {
                progress(options, `✔ PNPM ls recovered for workspace: ${formatContextLabel(options)} (depth=${depth})`);
            }
            if (persistToDisk) {
                await (0, utils_1.writeJsonFile)(targetFile, normalized);
            }
            return { ok: true, data: normalized, ...(persistToDisk ? { file: targetFile } : {}) };
        }
        const reason = describeAttemptFailure(result.code, result.stderr);
        progress(options, `✖ Failed pnpm ls for workspace: ${formatContextLabel(options)} (depth=${depth}; ${reason})`);
        const nextDepth = PNPM_DEPTH_ATTEMPTS[index + 1];
        if (nextDepth) {
            progress(options, `✔ Retrying pnpm ls for workspace: ${formatContextLabel(options)} (depth=${nextDepth})`);
        }
    }
    if (persistToDisk) {
        await (0, utils_1.writeJsonFile)(targetFile, {
            error: 'pnpm ls retries exhausted',
            nodeOptions: env.NODE_OPTIONS,
            attempts
        });
    }
    const sawOom = attempts.some((attempt) => attempt.outOfMemory);
    const lastAttempt = attempts[attempts.length - 1];
    if (sawOom) {
        return {
            ok: false,
            error: 'pnpm ls ran out of memory while building the dependency tree (retried with lower depths).',
            ...(persistToDisk ? { file: targetFile } : {})
        };
    }
    const suffix = lastAttempt && typeof lastAttempt.code === 'number'
        ? ` Last exit code: ${lastAttempt.code}.`
        : '';
    return {
        ok: false,
        error: `Failed to parse pnpm ls output after retries.${suffix}`,
        ...(persistToDisk ? { file: targetFile } : {})
    };
}
function progress(options, line) {
    if (typeof options.onProgress === 'function') {
        options.onProgress(line);
    }
}
function formatContextLabel(options) {
    var _a;
    const label = (_a = options.contextLabel) === null || _a === void 0 ? void 0 : _a.trim();
    return label || '(unknown package)';
}
function describeAttemptFailure(code, stderr) {
    if (isOutOfMemoryError(stderr))
        return 'out of memory';
    if (typeof code === 'number' && code !== 0)
        return `exit code ${code}`;
    if (code === null && stderr && stderr.trim())
        return 'terminated before completion';
    return 'no parseable JSON output';
}
function ensureNodeMaxOldSpaceSize(existing, megabytes) {
    const token = '--max-old-space-size=';
    if (typeof existing === 'string' && existing.includes(token)) {
        return existing;
    }
    const option = `${token}${megabytes}`;
    return existing && existing.trim() ? `${existing.trim()} ${option}` : option;
}
function isOutOfMemoryError(stderr) {
    return /heap out of memory|Reached heap limit|Allocation failed - JavaScript heap out of memory/i.test(stderr || '');
}
function trimText(text, maxChars) {
    if (!text)
        return '';
    const trimmed = text.trim();
    if (trimmed.length <= maxChars)
        return trimmed;
    return trimmed.slice(trimmed.length - maxChars);
}
function buildLsFailureMessage(tool, code, stderr) {
    if (isOutOfMemoryError(stderr)) {
        return `${tool} ls ran out of memory while building the dependency tree`;
    }
    if (typeof code === 'number' && code !== 0) {
        return `${tool} ls exited with code ${code}`;
    }
    if (code === null && stderr && stderr.trim()) {
        return `${tool} ls failed before completion`;
    }
    return `Failed to parse ${tool} ls output`;
}
function parseJsonOutput(raw) {
    if (!raw)
        return undefined;
    try {
        return JSON.parse(raw);
    }
    catch {
        // Some tools emit JSONL (yarn). Parse best-effort into an array of objects.
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
function normalizeNpmTree(data) {
    if (!data || typeof data !== 'object')
        return undefined;
    const deps = data.dependencies && typeof data.dependencies === 'object' ? data.dependencies : {};
    const normalized = { dependencies: {} };
    for (const [name, node] of Object.entries(deps)) {
        const normalizedNode = normalizeNpmNode(name, node);
        if (normalizedNode)
            normalized.dependencies[name] = normalizedNode;
    }
    return normalized;
}
function normalizeNpmNode(name, node) {
    if (!node || typeof node !== 'object')
        return undefined;
    if (node.missing || node.extraneous)
        return undefined;
    const version = typeof (node === null || node === void 0 ? void 0 : node.version) === 'string' ? node.version.trim() : '';
    if (!version || version === 'unknown' || version === 'missing' || version === 'invalid')
        return undefined;
    const out = { name, version, dependencies: {} };
    if (typeof node.path === 'string' && node.path.trim()) {
        out.path = node.path.trim();
    }
    if ((node === null || node === void 0 ? void 0 : node.dependencies) && typeof node.dependencies === 'object') {
        for (const [childName, child] of Object.entries(node.dependencies)) {
            const normalizedChild = normalizeNpmNode(childName, child);
            if (normalizedChild)
                out.dependencies[childName] = normalizedChild;
        }
    }
    if ((node === null || node === void 0 ? void 0 : node.dev) !== undefined)
        out.dev = Boolean(node.dev);
    if (out.dependencies && Object.keys(out.dependencies).length === 0) {
        delete out.dependencies;
    }
    return out;
}
function normalizePnpmTree(data, installState) {
    const roots = (Array.isArray(data) ? data : [data]).filter((entry) => entry && typeof entry === 'object');
    const root = roots.find((entry) => !isPnpmErrorPayload(entry));
    if (!root || typeof root !== 'object')
        return undefined;
    const dependencies = collectPnpmDependencyMap(root, installState);
    return { dependencies };
}
function isPnpmErrorPayload(node) {
    if (!node || typeof node !== 'object')
        return false;
    if (!('error' in node))
        return false;
    const error = node.error;
    return typeof error === 'string' || (error !== null && typeof error === 'object');
}
function collectPnpmDependencyMap(node, installState) {
    const out = {};
    const groups = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
    for (const group of groups) {
        const value = node === null || node === void 0 ? void 0 : node[group];
        if (!value)
            continue;
        if (Array.isArray(value)) {
            for (const entry of value) {
                if (!entry || typeof entry !== 'object')
                    continue;
                const name = typeof entry.name === 'string' ? entry.name : undefined;
                if (!name)
                    continue;
                const normalized = normalizePnpmNode(name, entry, installState);
                if (normalized)
                    out[name] = normalized;
            }
            continue;
        }
        if (typeof value === 'object') {
            for (const [name, entry] of Object.entries(value)) {
                if (!entry || typeof entry !== 'object')
                    continue;
                const normalized = normalizePnpmNode(name, entry, installState);
                if (normalized)
                    out[name] = normalized;
            }
        }
    }
    if (Object.keys(out).length > 0)
        return out;
    if ((node === null || node === void 0 ? void 0 : node.dependencies) && typeof node.dependencies === 'object') {
        for (const [name, entry] of Object.entries(node.dependencies)) {
            const normalized = normalizePnpmNode(name, entry, installState);
            if (normalized)
                out[name] = normalized;
        }
    }
    return out;
}
function normalizePnpmNode(name, node, installState) {
    const version = typeof (node === null || node === void 0 ? void 0 : node.version) === 'string' ? node.version.trim() : '';
    if (!version || version === 'unknown' || version === 'missing' || version === 'invalid')
        return undefined;
    if (!isPnpmPackageInstalled(name, version, installState))
        return undefined;
    const out = { name, version, dependencies: {} };
    const childMap = collectPnpmDependencyMap(node, installState);
    if (Object.keys(childMap).length > 0) {
        out.dependencies = childMap;
    }
    else {
        delete out.dependencies;
    }
    if ((node === null || node === void 0 ? void 0 : node.dev) !== undefined)
        out.dev = Boolean(node.dev);
    return out;
}
function createPnpmInstallState(projectPath) {
    const nodeModulesRoots = findNodeModulesRoots(projectPath);
    const virtualStoreEntries = new Set();
    for (const root of nodeModulesRoots) {
        const virtualStoreDir = path_1.default.join(root, '.pnpm');
        if (!safePathExists(virtualStoreDir))
            continue;
        for (const entry of safeReadDirNames(virtualStoreDir)) {
            virtualStoreEntries.add(entry);
        }
    }
    return {
        enabled: virtualStoreEntries.size > 0 || nodeModulesRoots.length > 0,
        virtualStoreEntries,
        nodeModulesRoots,
        installedCache: new Map()
    };
}
function findNodeModulesRoots(startPath) {
    const roots = [];
    let current = path_1.default.resolve(startPath);
    while (true) {
        const candidate = path_1.default.join(current, 'node_modules');
        if (safePathExists(candidate)) {
            roots.push(candidate);
        }
        const parent = path_1.default.dirname(current);
        if (parent === current)
            break;
        current = parent;
    }
    return roots;
}
function isPnpmPackageInstalled(name, version, installState) {
    if (!installState.enabled)
        return true;
    const cacheKey = `${name}@${version}`;
    const cached = installState.installedCache.get(cacheKey);
    if (cached !== undefined)
        return cached;
    const normalizedName = normalizeScopedPackageNameForPnpmStore(name);
    const storePrefix = `${normalizedName}@${version}`;
    for (const entry of installState.virtualStoreEntries) {
        if (entry === storePrefix || entry.startsWith(`${storePrefix}_`) || entry.startsWith(`${storePrefix}(`)) {
            installState.installedCache.set(cacheKey, true);
            return true;
        }
    }
    // Workspace links may resolve outside the virtual store, but still exist in node_modules.
    for (const nodeModulesRoot of installState.nodeModulesRoots) {
        const packageDir = path_1.default.join(nodeModulesRoot, ...name.split('/'));
        if (safePathExists(packageDir) && packageDirectoryMatchesVersion(packageDir, version)) {
            installState.installedCache.set(cacheKey, true);
            return true;
        }
    }
    installState.installedCache.set(cacheKey, false);
    return false;
}
function normalizeScopedPackageNameForPnpmStore(name) {
    if (!name.startsWith('@'))
        return name;
    const slashIndex = name.indexOf('/');
    if (slashIndex <= 0)
        return name;
    return `${name.slice(0, slashIndex)}+${name.slice(slashIndex + 1)}`;
}
function safePathExists(targetPath) {
    try {
        return fs_1.default.existsSync(targetPath);
    }
    catch {
        return false;
    }
}
function safeReadDirNames(dirPath) {
    try {
        return fs_1.default.readdirSync(dirPath);
    }
    catch {
        return [];
    }
}
function packageDirectoryMatchesVersion(packageDir, expectedVersion) {
    const pkgJsonPath = path_1.default.join(packageDir, 'package.json');
    if (!safePathExists(pkgJsonPath))
        return true;
    try {
        const raw = fs_1.default.readFileSync(pkgJsonPath, 'utf8');
        const parsed = JSON.parse(raw);
        const version = typeof (parsed === null || parsed === void 0 ? void 0 : parsed.version) === 'string' ? parsed.version.trim() : '';
        return !version || version === expectedVersion;
    }
    catch {
        return true;
    }
}
function normalizeYarnTree(data) {
    const treePayload = resolveYarnTreePayload(data);
    if (!treePayload || !Array.isArray(treePayload.trees))
        return undefined;
    const out = { dependencies: {} };
    for (const node of treePayload.trees) {
        const parsed = normalizeYarnNode(node);
        if (parsed)
            out.dependencies[parsed.name] = parsed.node;
    }
    return out;
}
function resolveYarnTreePayload(data) {
    var _a;
    if (!data)
        return undefined;
    if ((_a = data === null || data === void 0 ? void 0 : data.data) === null || _a === void 0 ? void 0 : _a.trees)
        return data.data;
    if (data === null || data === void 0 ? void 0 : data.trees)
        return data;
    if (Array.isArray(data)) {
        const treeItem = data.find((item) => { var _a; return item && typeof item === 'object' && item.type === 'tree' && ((_a = item.data) === null || _a === void 0 ? void 0 : _a.trees); });
        return treeItem === null || treeItem === void 0 ? void 0 : treeItem.data;
    }
    return undefined;
}
function normalizeYarnNode(node) {
    if (!node || typeof node !== 'object')
        return undefined;
    const label = typeof node.name === 'string' ? node.name : '';
    const parsed = splitYarnLabel(label);
    if (!parsed.version || parsed.version === 'unknown' || parsed.version === 'missing' || parsed.version === 'invalid')
        return undefined;
    const out = { name: parsed.name, version: parsed.version, dependencies: {} };
    if (Array.isArray(node.children)) {
        for (const child of node.children) {
            const parsedChild = normalizeYarnNode(child);
            if (parsedChild) {
                out.dependencies[parsedChild.name] = parsedChild.node;
            }
        }
    }
    if (out.dependencies && Object.keys(out.dependencies).length === 0) {
        delete out.dependencies;
    }
    return { name: parsed.name, node: out };
}
function splitYarnLabel(label) {
    if (!label)
        return { name: 'unknown', version: 'unknown' };
    const lastAt = label.lastIndexOf('@');
    if (lastAt <= 0)
        return { name: label, version: 'unknown' };
    const name = label.slice(0, lastAt);
    let version = label.slice(lastAt + 1);
    if (version.startsWith('npm:')) {
        version = version.slice(4);
    }
    return { name, version: version || 'unknown' };
}
