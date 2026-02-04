"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runNpmLs = runNpmLs;
const path_1 = __importDefault(require("path"));
const utils_1 = require("../utils");
// Normalize package-manager-specific list output into a shared dependency tree.
async function runNpmLs(projectPath, tempDir, tool = 'npm') {
    const targetFile = path_1.default.join(tempDir, `${tool}-ls.json`);
    try {
        const { args, normalize } = buildLsCommand(tool);
        const result = await (0, utils_1.runCommand)(tool, args, { cwd: projectPath });
        const parsed = parseJsonOutput(result.stdout);
        const normalized = normalize(parsed);
        if (normalized) {
            await (0, utils_1.writeJsonFile)(targetFile, normalized);
            return { ok: true, data: normalized, file: targetFile };
        }
        await (0, utils_1.writeJsonFile)(targetFile, { stdout: result.stdout, stderr: result.stderr, code: result.code });
        const error = result.code && result.code !== 0
            ? `${tool} ls exited with code ${result.code}`
            : `Failed to parse ${tool} ls output`;
        return { ok: false, error, file: targetFile };
    }
    catch (err) {
        await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        return { ok: false, error: `${tool} ls failed: ${String(err)}`, file: targetFile };
    }
}
function buildLsCommand(tool) {
    if (tool === 'pnpm') {
        return {
            args: ['list', '--json', '--depth', 'Infinity'],
            normalize: normalizePnpmTree
        };
    }
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
function normalizePnpmTree(data) {
    const roots = Array.isArray(data) ? data : [data];
    const root = roots.find((entry) => entry && typeof entry === 'object');
    if (!root || typeof root !== 'object')
        return undefined;
    const dependencies = collectPnpmDependencyMap(root);
    return { dependencies };
}
function collectPnpmDependencyMap(node) {
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
                const normalized = normalizePnpmNode(name, entry);
                if (normalized)
                    out[name] = normalized;
            }
            continue;
        }
        if (typeof value === 'object') {
            for (const [name, entry] of Object.entries(value)) {
                if (!entry || typeof entry !== 'object')
                    continue;
                const normalized = normalizePnpmNode(name, entry);
                if (normalized)
                    out[name] = normalized;
            }
        }
    }
    if (Object.keys(out).length > 0)
        return out;
    if ((node === null || node === void 0 ? void 0 : node.dependencies) && typeof node.dependencies === 'object') {
        for (const [name, entry] of Object.entries(node.dependencies)) {
            const normalized = normalizePnpmNode(name, entry);
            if (normalized)
                out[name] = normalized;
        }
    }
    return out;
}
function normalizePnpmNode(name, node) {
    const version = typeof (node === null || node === void 0 ? void 0 : node.version) === 'string' ? node.version.trim() : '';
    if (!version || version === 'unknown' || version === 'missing' || version === 'invalid')
        return undefined;
    const out = { name, version, dependencies: {} };
    const childMap = collectPnpmDependencyMap(node);
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
