"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runImportGraph = runImportGraph;
exports.extractImports = extractImports;
const path_1 = __importDefault(require("path"));
const promises_1 = __importDefault(require("fs/promises"));
const module_1 = require("module");
const utils_1 = require("../utils");
const IGNORED_DIRS = new Set([
    'node_modules',
    'dist',
    'build',
    'coverage',
    'storybook-static',
    '.dependency-radar'
]);
const SOURCE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];
/**
 * Builds an import graph for a project and optionally writes it to disk.
 *
 * The produced graph maps each project-relative source file to its resolved local file dependencies,
 * referenced packages, per-file package usage counts, and any unresolved import specifiers.
 *
 * @param options - Optional settings.
 * @param options.persistToDisk - When `false`, the graph is not written to disk; defaults to `true`.
 * @returns An object with:
 *  - `ok: true` and `data` containing `{ files, packages, packageCounts, unresolvedImports }` on success.
 *    When the graph was persisted to disk, a `file` field points to the written JSON file (`<tempDir>/import-graph.json`).
 *  - `ok: false` and `error` containing an error message on failure. If persistence was enabled, a `file` field may point to
 *    the JSON file containing the error object.
 */
async function runImportGraph(projectPath, tempDir, options = {}) {
    const persistToDisk = options.persistToDisk !== false;
    const targetFile = path_1.default.join(tempDir, 'import-graph.json');
    try {
        const files = await collectSourceFiles(projectPath);
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
        if (persistToDisk) {
            await (0, utils_1.writeJsonFile)(targetFile, output);
        }
        return { ok: true, data: output, ...(persistToDisk ? { file: targetFile } : {}) };
    }
    catch (err) {
        if (persistToDisk) {
            await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        }
        return {
            ok: false,
            error: `import graph failed: ${String(err)}`,
            ...(persistToDisk ? { file: targetFile } : {})
        };
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
/**
 * Blank out comments so import-looking text inside them can't register as
 * evidence. Regex literals are recognised with the standard preceding-token
 * heuristic so `/[/*]/` or `://` inside them are not mistaken for comments;
 * string literals are left alone (the import patterns demand surrounding
 * syntax anyway). Positions are preserved (comments become spaces). If a
 * block comment is unterminated the original content is returned unchanged —
 * failing open to the old behaviour beats blanking a file to EOF.
 */
function stripComments(content) {
    let out = '';
    let i = 0;
    let quote;
    let escaped = false;
    let maskStrings = false;
    // Last non-whitespace character emitted outside strings/comments; a '/'
    // after one of these starts a regex literal, not division.
    let prevSignificant = '';
    // Trailing identifier word, so regexes after keywords (return /x/) are
    // recognised even though the preceding character is a letter.
    let prevWord = '';
    let wordBroken = false;
    const regexPreceders = new Set([
        '', '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '<', '>', '+', '-', '*', '%', '~', '^',
    ]);
    const regexPrecederWords = new Set([
        'return', 'typeof', 'instanceof', 'case', 'in', 'of', 'delete', 'void', 'new', 'do', 'else', 'yield', 'await',
    ]);
    while (i < content.length) {
        const ch = content[i];
        const next = content[i + 1];
        if (quote) {
            if (escaped) {
                escaped = false;
                out += maskStrings ? ' ' : ch;
            }
            else if (ch === '\\') {
                escaped = true;
                out += maskStrings ? ' ' : ch;
            }
            else if (ch === quote) {
                quote = undefined;
                out += ch;
            }
            else {
                // Inside a non-specifier string: blank the content so text like
                // "require('ghost-pkg')" in documentation strings can't register
                // as import evidence. Newlines survive so positions keep meaning.
                out += maskStrings && ch !== '\n' ? ' ' : ch;
            }
            i += 1;
            continue;
        }
        if (ch === '"' || ch === "'" || ch === '`') {
            quote = ch;
            // Only strings sitting in import-specifier position keep their
            // contents: after `from`, `import`/`import(`, `export`, `require(`.
            // Template literals are never specifiers. Test just the tail — an
            // end-anchored regex over the whole accumulator goes quadratic on
            // large files.
            maskStrings =
                ch === '`' ||
                    !/(?:\bfrom|\bimport|\bexport|\brequire\s*\(|\bimport\s*\()\s*$/.test(out.slice(-24));
            out += ch;
            prevSignificant = ch;
            i += 1;
            continue;
        }
        if (ch === '/' && (next === '/' || next === '*')) {
            if (next === '/') {
                while (i < content.length && content[i] !== '\n') {
                    out += ' ';
                    i += 1;
                }
                continue;
            }
            const close = content.indexOf('*/', i + 2);
            if (close === -1)
                return content; // unterminated — fail open
            for (let j = i; j < close + 2; j += 1) {
                out += content[j] === '\n' ? '\n' : ' ';
            }
            i = close + 2;
            continue;
        }
        if (ch === '/' &&
            (regexPreceders.has(prevSignificant) || regexPrecederWords.has(prevWord))) {
            // Consume a regex literal (with character classes), masking its body:
            // regex text can contain anything, including import-shaped strings,
            // and must never register as evidence.
            out += ch;
            i += 1;
            let inClass = false;
            let regexEscaped = false;
            while (i < content.length) {
                const rc = content[i];
                i += 1;
                if (regexEscaped) {
                    regexEscaped = false;
                    out += ' ';
                    continue;
                }
                if (rc === '\\') {
                    regexEscaped = true;
                    out += ' ';
                    continue;
                }
                if (rc === '[')
                    inClass = true;
                else if (rc === ']')
                    inClass = false;
                if (rc === '/' && !inClass) {
                    out += '/';
                    break;
                }
                if (rc === '\n') {
                    out += '\n'; // not actually a regex — bail out
                    break;
                }
                out += ' ';
            }
            prevSignificant = '/';
            prevWord = '';
            continue;
        }
        out += ch;
        if (!/\s/.test(ch))
            prevSignificant = ch;
        if (/[A-Za-z0-9_$]/.test(ch)) {
            prevWord = wordBroken ? ch : prevWord + ch;
            wordBroken = false;
        }
        else if (/\s/.test(ch)) {
            wordBroken = true;
        }
        else {
            prevWord = '';
            wordBroken = false;
        }
        i += 1;
    }
    return out;
}
/** True for type-only import/export statements, erased at compile time. */
function isTypeOnlyStatement(matchedText) {
    return /^(?:import|export)\s+type[\s{*]/.test(matchedText);
}
function extractImports(content) {
    const matches = [];
    const stripped = stripComments(content);
    const patterns = [
        /\bimport\s+(?:[^'"]+from\s+)?['"]([^'"]+)['"]/g,
        /\bexport\s+(?:[^'"]+from\s+)?['"]([^'"]+)['"]/g,
        /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g,
        /\bimport\(\s*['"]([^'"]+)['"]\s*\)/g
    ];
    // TypeScript import() type queries (`type X = import('pkg').Y`) are
    // erased at compile time: a dynamic-import match whose statement starts
    // with a type-alias declaration is not runtime evidence.
    const inTypeAlias = (index) => {
        const lineStart = stripped.lastIndexOf('\n', index - 1) + 1;
        const prefix = stripped.slice(lineStart, index);
        return /(?:^|[;{])\s*(?:export\s+)?type\s+[A-Za-z0-9_$]+(?:<[^=]*>)?\s*=[^;]*$/.test(prefix);
    };
    for (const pattern of patterns) {
        let match;
        while ((match = pattern.exec(stripped)) !== null) {
            // Type-only imports/exports never load the package at runtime; checking
            // the matched statement itself (not a precomputed span) keeps the
            // exclusion from bleeding across statement boundaries.
            if (!match[1] || isTypeOnlyStatement(match[0]))
                continue;
            if (match[0].startsWith('import(') || /^import\s*\(/.test(match[0])) {
                if (inTypeAlias(match.index))
                    continue;
            }
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
