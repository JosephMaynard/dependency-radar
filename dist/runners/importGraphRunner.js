"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runImportGraph = runImportGraph;
const path_1 = __importDefault(require("path"));
const promises_1 = __importDefault(require("fs/promises"));
const module_1 = require("module");
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
        const fileGraph = {};
        const packageGraph = {};
        const packageCounts = {};
        const unresolvedImports = [];
        for (const file of files) {
            const rel = normalizePath(projectPath, file);
            const content = await promises_1.default.readFile(file, 'utf8');
            const imports = extractImports(content);
            const resolved = await resolveImports(imports, path_1.default.dirname(file), projectPath);
            fileGraph[rel] = resolved.files;
            packageGraph[rel] = resolved.packages;
            packageCounts[rel] = resolved.packageCounts;
            unresolvedImports.push(...resolved.unresolved.map((spec) => ({ importer: rel, specifier: spec })));
        }
        const output = { files: fileGraph, packages: packageGraph, packageCounts, unresolvedImports };
        await (0, utils_1.writeJsonFile)(targetFile, output);
        return { ok: true, data: output, file: targetFile };
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
    const matches = [];
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
                matches.push(match[1]);
        }
    }
    return matches;
}
async function resolveImports(specifiers, fileDir, projectPath) {
    const resolvedFiles = [];
    const resolvedPackages = [];
    const packageCounts = {};
    const unresolved = [];
    for (const spec of specifiers) {
        if (isBuiltinModule(spec))
            continue;
        if (spec.startsWith('.') || spec.startsWith('/')) {
            const target = await resolveFileTarget(spec, fileDir, projectPath);
            if (target) {
                resolvedFiles.push(target);
            }
            else {
                unresolved.push(spec);
            }
        }
        else {
            const pkgName = toPackageName(spec);
            resolvedPackages.push(pkgName);
            packageCounts[pkgName] = (packageCounts[pkgName] || 0) + 1;
        }
    }
    return {
        files: uniqSorted(resolvedFiles),
        packages: uniqSorted(resolvedPackages),
        packageCounts,
        unresolved: uniqSorted(unresolved)
    };
}
async function resolveFileTarget(spec, fileDir, projectPath) {
    const base = spec.startsWith('/')
        ? path_1.default.resolve(projectPath, `.${spec}`)
        : path_1.default.resolve(fileDir, spec);
    const direct = await resolveFile(base);
    if (direct)
        return normalizePath(projectPath, direct);
    return undefined;
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
const BUILTIN_MODULES = new Set(module_1.builtinModules.flatMap((mod) => (mod.startsWith('node:') ? [mod, mod.slice(5)] : [mod])));
function isBuiltinModule(spec) {
    const normalized = spec.startsWith('node:') ? spec.slice(5) : spec;
    if (BUILTIN_MODULES.has(spec) || BUILTIN_MODULES.has(normalized))
        return true;
    const root = normalized.split('/')[0];
    return BUILTIN_MODULES.has(root);
}
function uniqSorted(values) {
    return Array.from(new Set(values)).sort();
}
