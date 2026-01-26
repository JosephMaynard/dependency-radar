"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runImportGraph = runImportGraph;
const path_1 = __importDefault(require("path"));
const promises_1 = __importDefault(require("fs/promises"));
const utils_1 = require("../utils");
const IGNORED_DIRS = new Set(['node_modules', 'dist', 'build', 'coverage', '.dependency-radar']);
const SOURCE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];
async function runImportGraph(projectPath, tempDir) {
    const targetFile = path_1.default.join(tempDir, 'import-graph.json');
    try {
        const srcPath = path_1.default.join(projectPath, 'src');
        const hasSrc = await (0, utils_1.pathExists)(srcPath);
        const entry = hasSrc ? srcPath : projectPath;
        const files = await collectSourceFiles(entry);
        const graph = {};
        for (const file of files) {
            const rel = normalizePath(projectPath, file);
            const content = await promises_1.default.readFile(file, 'utf8');
            const imports = extractImports(content);
            const resolved = await resolveImports(imports, path_1.default.dirname(file), projectPath);
            graph[rel] = resolved;
        }
        await (0, utils_1.writeJsonFile)(targetFile, graph);
        return { ok: true, data: graph, file: targetFile };
    }
    catch (err) {
        await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        return { ok: false, error: `import graph failed: ${String(err)}`, file: targetFile };
    }
}
async function collectSourceFiles(rootDir) {
    const files = [];
    async function walk(current) {
        const entries = await promises_1.default.readdir(current, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.name.startsWith('.'))
                continue;
            const fullPath = path_1.default.join(current, entry.name);
            if (entry.isDirectory()) {
                if (IGNORED_DIRS.has(entry.name))
                    continue;
                await walk(fullPath);
            }
            else if (entry.isFile()) {
                if (SOURCE_EXTENSIONS.includes(path_1.default.extname(entry.name))) {
                    files.push(fullPath);
                }
            }
        }
    }
    await walk(rootDir);
    return files;
}
function extractImports(content) {
    const matches = new Set();
    const patterns = [
        /\bimport\s+(?:[^'"]+from\s+)?['"]([^'"]+)['"]/g,
        /\bexport\s+(?:[^'"]+from\s+)?['"]([^'"]+)['"]/g,
        /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g,
        /\bimport\(\s*['"]([^'"]+)['"]\s*\)/g
    ];
    for (const pattern of patterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
            if (match[1])
                matches.add(match[1]);
        }
    }
    return Array.from(matches);
}
async function resolveImports(specifiers, fileDir, projectPath) {
    const resolved = [];
    for (const spec of specifiers) {
        if (spec.startsWith('.') || spec.startsWith('/')) {
            const target = await resolveFileTarget(spec, fileDir, projectPath);
            if (target)
                resolved.push(target);
        }
        else {
            resolved.push(toPackageName(spec));
        }
    }
    return resolved;
}
async function resolveFileTarget(spec, fileDir, projectPath) {
    const base = spec.startsWith('/')
        ? path_1.default.resolve(projectPath, `.${spec}`)
        : path_1.default.resolve(fileDir, spec);
    const direct = await resolveFile(base);
    if (direct)
        return normalizePath(projectPath, direct);
    return normalizePath(projectPath, base);
}
async function resolveFile(basePath) {
    if (await isFile(basePath))
        return basePath;
    for (const ext of SOURCE_EXTENSIONS) {
        const candidate = `${basePath}${ext}`;
        if (await isFile(candidate))
            return candidate;
    }
    if (await isDir(basePath)) {
        for (const ext of SOURCE_EXTENSIONS) {
            const candidate = path_1.default.join(basePath, `index${ext}`);
            if (await isFile(candidate))
                return candidate;
        }
    }
    return undefined;
}
async function isFile(target) {
    try {
        const stat = await promises_1.default.stat(target);
        return stat.isFile();
    }
    catch {
        return false;
    }
}
async function isDir(target) {
    try {
        const stat = await promises_1.default.stat(target);
        return stat.isDirectory();
    }
    catch {
        return false;
    }
}
function toPackageName(spec) {
    if (spec.startsWith('@')) {
        const parts = spec.split('/');
        return parts.slice(0, 2).join('/');
    }
    return spec.split('/')[0];
}
function normalizePath(baseDir, filePath) {
    const rel = path_1.default.relative(baseDir, filePath);
    return rel.split(path_1.default.sep).join('/');
}
