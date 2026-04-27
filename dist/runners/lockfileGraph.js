"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.tryBuildDependencyTreeFromLockfile = tryBuildDependencyTreeFromLockfile;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const lockfileParsers_1 = require("./lockfileParsers");
const treeCache = new Map();
const parseCache = new Map();
/**
 * Builds a dependency tree from the project's package manager lockfile, using cached results when available.
 *
 * @param projectPath - Filesystem path of the project (used to locate package.json and determine the lockfile context)
 * @param tool - Package manager to parse (`npm`, `pnpm`, or `yarn`)
 * @param lockfileSearchRoot - Optional directory to start upward lockfile lookup; defaults to `projectPath`
 * @returns A LockfileTreeResult containing the lockfile `sourceFile` and resolved dependency `data`, or `undefined` if no valid lockfile could be found or parsed
 */
async function tryBuildDependencyTreeFromLockfile(projectPath, tool, lockfileSearchRoot) {
    const searchRoot = path_1.default.resolve(lockfileSearchRoot || projectPath);
    const cacheKey = `${tool}:${path_1.default.resolve(projectPath)}:${searchRoot}`;
    if (treeCache.has(cacheKey)) {
        const cached = treeCache.get(cacheKey);
        return cached || undefined;
    }
    try {
        let result;
        if (tool === 'pnpm') {
            result = parsePnpmTree(projectPath, searchRoot);
        }
        else if (tool === 'npm') {
            result = parseNpmTree(projectPath, searchRoot);
        }
        else if (tool === 'yarn') {
            result = parseYarnTree(projectPath, searchRoot);
        }
        else {
            result = parseBunTree(projectPath, searchRoot);
        }
        treeCache.set(cacheKey, result || null);
        return result;
    }
    catch {
        treeCache.set(cacheKey, null);
        return undefined;
    }
}
function stripJsonComments(raw) {
    let out = '';
    let quote;
    let escaped = false;
    for (let i = 0; i < raw.length; i += 1) {
        const ch = raw[i];
        const next = raw[i + 1];
        if (quote) {
            out += ch;
            if (escaped)
                escaped = false;
            else if (ch === '\\')
                escaped = true;
            else if (ch === quote)
                quote = undefined;
            continue;
        }
        if (ch === '"' || ch === "'") {
            quote = ch;
            out += ch;
            continue;
        }
        if (ch === '/' && next === '/') {
            while (i < raw.length && raw[i] !== '\n')
                i += 1;
            out += '\n';
            continue;
        }
        if (ch === '/' && next === '*') {
            i += 2;
            while (i < raw.length && !(raw[i] === '*' && raw[i + 1] === '/'))
                i += 1;
            i += 1;
            continue;
        }
        out += ch;
    }
    return out.replace(/,\s*([}\]])/g, '$1');
}
function parseBunTree(projectPath, searchRoot) {
    const lockPath = findUpwards(projectPath, ['bun.lock'], searchRoot);
    if (!lockPath)
        return undefined;
    const raw = readCachedText(lockPath);
    if (!raw)
        return undefined;
    const packageJsonPath = path_1.default.join(projectPath, 'package.json');
    if (!safePathExists(packageJsonPath))
        return undefined;
    const packageJson = readJsonSafe(packageJsonPath);
    if (!packageJson || typeof packageJson !== 'object')
        return undefined;
    if (raw.trim().startsWith('{')) {
        const parsed = readBunJsonLock(raw);
        if (parsed) {
            return { sourceFile: lockPath, data: buildBunJsonResolvedTree(parsed, packageJson) };
        }
    }
    const yarnLike = parseYarnV1(raw) || parseYarnV2(raw);
    if (!yarnLike)
        return undefined;
    return { sourceFile: lockPath, data: buildYarnResolvedTree(yarnLike, packageJson) };
}
function readBunJsonLock(raw) {
    try {
        return JSON.parse(stripJsonComments(raw));
    }
    catch {
        return undefined;
    }
}
function buildBunJsonResolvedTree(lock, packageJson) {
    const packages = (lock === null || lock === void 0 ? void 0 : lock.packages) && typeof lock.packages === 'object' ? lock.packages : {};
    const rootDeps = collectPackageJsonDependencySpecs(packageJson);
    const dependencies = {};
    const memo = new Map();
    const stack = new Set();
    for (const [depName, depSpec] of Object.entries(rootDeps)) {
        const node = buildBunJsonNode(depName, depSpec, packages, memo, stack);
        if (node)
            dependencies[node.name] = node;
    }
    return { dependencies };
}
function normalizeBunPackageEntry(rawEntry) {
    const entry = Array.isArray(rawEntry)
        ? rawEntry.find((item) => item && typeof item === 'object' && !Array.isArray(item))
        : rawEntry;
    if (!entry || typeof entry !== 'object')
        return undefined;
    const version = typeof entry.version === 'string'
        ? entry.version
        : typeof entry.resolution === 'string'
            ? extractVersionFromBunResolution(entry.resolution)
            : undefined;
    return {
        ...(version ? { version } : {}),
        ...(entry.dependencies && typeof entry.dependencies === 'object' ? { dependencies: entry.dependencies } : {}),
        ...(entry.optionalDependencies && typeof entry.optionalDependencies === 'object' ? { optionalDependencies: entry.optionalDependencies } : {})
    };
}
function extractVersionFromBunResolution(value) {
    const match = value.match(/@npm:([^#\s]+)/);
    return match ? match[1] : undefined;
}
function findBunPackageEntry(name, spec, packages) {
    const exactKey = `${name}@${spec}`;
    if (packages[exactKey])
        return packages[exactKey];
    if (packages[name])
        return packages[name];
    const prefix = `${name}@`;
    const key = Object.keys(packages).find((candidate) => candidate === name || candidate.startsWith(prefix));
    return key ? packages[key] : undefined;
}
function buildBunJsonNode(name, spec, packages, memo, stack) {
    const memoKey = `${name}@${spec}`;
    if (memo.has(memoKey))
        return memo.get(memoKey);
    if (stack.has(memoKey))
        return undefined;
    const entry = normalizeBunPackageEntry(findBunPackageEntry(name, spec, packages));
    if (!(entry === null || entry === void 0 ? void 0 : entry.version))
        return undefined;
    const out = { name, version: entry.version, dependencies: {} };
    stack.add(memoKey);
    const childDeps = mergeStringRecord(entry.dependencies, entry.optionalDependencies);
    for (const childName of Object.keys(childDeps)) {
        if (isWorkspaceLikeSpecifier(childDeps[childName]))
            continue;
        const child = buildBunJsonNode(childName, childDeps[childName], packages, memo, stack);
        if (child)
            out.dependencies[child.name] = child;
    }
    stack.delete(memoKey);
    if (out.dependencies && Object.keys(out.dependencies).length === 0)
        delete out.dependencies;
    memo.set(memoKey, out);
    return out;
}
/**
 * Builds a dependency tree from a pnpm lockfile for the given project path.
 *
 * Locates the nearest pnpm-lock.yaml, resolves the appropriate importer for the project,
 * and constructs a normalized ResolvedTree of root dependencies by traversing pnpm package snapshots.
 *
 * @param projectPath - Filesystem path to the project directory used to locate the lockfile and determine the importer
 * @param searchRoot - Optional directory at which to stop the upward search for pnpm-lock.yaml
 * @returns A LockfileTreeResult containing `sourceFile` (the resolved lockfile path) and `data` (the resolved dependency tree),
 * or `undefined` if the lockfile, importer, or required parsed data cannot be found or parsed
 */
function parsePnpmTree(projectPath, searchRoot) {
    const lockPath = findUpwards(projectPath, ['pnpm-lock.yaml'], searchRoot);
    if (!lockPath)
        return undefined;
    const parsed = getCachedYaml(lockPath);
    if (!parsed || typeof parsed !== 'object')
        return undefined;
    const importers = parsed.importers && typeof parsed.importers === 'object' ? parsed.importers : undefined;
    if (!importers)
        return undefined;
    const lockDir = path_1.default.dirname(lockPath);
    const importerKey = resolvePnpmImporterKey(projectPath, lockDir, importers);
    if (!importerKey)
        return undefined;
    const importer = importers[importerKey];
    if (!importer || typeof importer !== 'object')
        return undefined;
    const packageSnapshots = buildPnpmSnapshotMap(parsed.packages, parsed.snapshots);
    const packageIndex = buildPnpmIndex(packageSnapshots);
    const installState = createPnpmInstallState(projectPath);
    const memo = new Map();
    const rootDeps = collectPnpmImporterDependencies(importer);
    const dependencies = {};
    for (const [depName, depRef] of Object.entries(rootDeps)) {
        const resolved = resolvePnpmDependency(depName, depRef, packageIndex);
        if (!resolved)
            continue;
        const node = buildPnpmNode(resolved.packageKey, packageSnapshots, packageIndex, memo, installState, new Set());
        if (node)
            dependencies[node.name] = node;
    }
    return {
        sourceFile: lockPath,
        data: { dependencies }
    };
}
/**
 * Determine the importer key in a pnpm lockfile that corresponds to a project path.
 *
 * @param projectPath - Absolute path to the project whose importer key should be resolved
 * @param lockDir - Directory containing the pnpm lockfile
 * @param importers - The `importers` object from the parsed pnpm lockfile
 * @returns The matching importer key from `importers`, or `undefined` if no match is found
 */
function resolvePnpmImporterKey(projectPath, lockDir, importers) {
    const rel = toPosixRelative(lockDir, projectPath);
    const normalized = rel === '' ? '.' : rel;
    const candidates = [normalized, normalized.replace(/^\.\//, '')];
    if (normalized !== '.') {
        candidates.push(`./${normalized}`);
    }
    for (const candidate of candidates) {
        if (candidate in importers)
            return candidate;
    }
    if ('.' in importers && normalized === '.') {
        return '.';
    }
    return undefined;
}
/**
 * Merge pnpm `packages` and `snapshots` maps into a single map of package keys to combined metadata.
 *
 * @param packages - Map of packageKey to package metadata (may be undefined)
 * @param snapshots - Map of packageKey to snapshot metadata (may be undefined)
 * @returns A map where each key is a packageKey and the value is the merged metadata object. Top-level snapshot fields override package fields when present; `dependencies`, `optionalDependencies`, and `peerDependencies` are merged with snapshot entries taking precedence over package entries.
 */
function buildPnpmSnapshotMap(packages, snapshots) {
    const out = {};
    const keys = new Set([
        ...Object.keys(packages || {}),
        ...Object.keys(snapshots || {})
    ]);
    for (const key of keys) {
        const pkg = packages === null || packages === void 0 ? void 0 : packages[key];
        const snap = snapshots === null || snapshots === void 0 ? void 0 : snapshots[key];
        out[key] = {
            ...(pkg && typeof pkg === 'object' ? pkg : {}),
            ...(snap && typeof snap === 'object' ? snap : {}),
            dependencies: mergeStringRecord(pkg === null || pkg === void 0 ? void 0 : pkg.dependencies, snap === null || snap === void 0 ? void 0 : snap.dependencies),
            optionalDependencies: mergeStringRecord(pkg === null || pkg === void 0 ? void 0 : pkg.optionalDependencies, snap === null || snap === void 0 ? void 0 : snap.optionalDependencies),
            peerDependencies: mergeStringRecord(pkg === null || pkg === void 0 ? void 0 : pkg.peerDependencies, snap === null || snap === void 0 ? void 0 : snap.peerDependencies)
        };
    }
    return out;
}
/**
 * Build lookup maps that resolve pnpm package keys by exact and stripped package identifiers.
 *
 * Creates two maps: one mapping the full `name@ref` (exact) to the original package key, and
 * another mapping `name@ref` with any pnpm peer suffix removed (stripped) to the original package key.
 *
 * @param snapshots - The pnpm packages/snapshots object keyed by packageKey from the lockfile
 * @returns An object containing:
 *  - `byExact`: Map from `name@ref` to the original packageKey
 *  - `byStripped`: Map from `name@ref` (with peer suffix removed) to the original packageKey
 */
function buildPnpmIndex(snapshots) {
    const byExact = new Map();
    const byStripped = new Map();
    for (const packageKey of Object.keys(snapshots)) {
        const parsed = parsePnpmPackageKey(packageKey);
        if (!parsed)
            continue;
        const exact = `${parsed.name}@${parsed.ref}`;
        const stripped = `${parsed.name}@${stripPnpmPeerSuffix(parsed.ref)}`;
        if (!byExact.has(exact))
            byExact.set(exact, packageKey);
        if (!byStripped.has(stripped))
            byStripped.set(stripped, packageKey);
    }
    return { byExact, byStripped };
}
/**
 * Collects declared dependency references from a pnpm importer section.
 *
 * @param importer - The importer object from a pnpm lockfile (an entry under `importers`) containing dependency sections.
 * @returns A map from dependency name to its lockfile reference string; excludes entries with missing/invalid refs or workspace-like specifiers.
 */
function collectPnpmImporterDependencies(importer) {
    const out = {};
    for (const key of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        const section = importer === null || importer === void 0 ? void 0 : importer[key];
        if (!section || typeof section !== 'object')
            continue;
        for (const [depName, rawValue] of Object.entries(section)) {
            const ref = extractPnpmRef(rawValue);
            if (!ref)
                continue;
            if (isWorkspaceLikeSpecifier(ref))
                continue;
            out[depName] = ref;
        }
    }
    return out;
}
/**
 * Resolve a pnpm dependency reference to the corresponding lockfile package key.
 *
 * @param dependencyName - The dependency name used when resolving aliases.
 * @param rawRef - The raw pnpm reference string from the lockfile.
 * @param index - Lookup maps: `byExact` maps exact `name@ref` keys to package keys, `byStripped` maps peer-stripped `name@ref` keys to package keys.
 * @returns `{ packageKey }` with the matched package key, or `undefined` if the reference cannot be resolved.
 */
function resolvePnpmDependency(dependencyName, rawRef, index) {
    const normalized = normalizePnpmRef(rawRef, dependencyName);
    if (!normalized)
        return undefined;
    const exact = `${normalized.name}@${normalized.ref}`;
    const stripped = `${normalized.name}@${stripPnpmPeerSuffix(normalized.ref)}`;
    const packageKey = index.byExact.get(exact) ||
        index.byStripped.get(stripped) ||
        (normalized.ref.startsWith('/') ? index.byExact.get(`${normalized.name}@${normalized.ref.slice(1)}`) : undefined);
    if (!packageKey)
        return undefined;
    return { packageKey };
}
/**
 * Build a ResolvedNode for a pnpm package key by resolving its snapshot entry and recursively attaching installed child dependencies.
 *
 * @param packageKey - The pnpm package key (as found in lockfile snapshots) to resolve.
 * @param snapshots - Map of packageKey to merged snapshot/package metadata used to look up dependency refs.
 * @param index - Lookup maps (`byExact`, `byStripped`) used to resolve dependency refs to package keys.
 * @param memo - Memoization cache mapping packageKey to previously built ResolvedNode or `undefined`; populated with the result before returning.
 * @param installState - pnpm install state used to determine whether a package is considered installed locally.
 * @param stack - Set used for cycle detection during recursive construction; the function adds and removes entries as it descends.
 * @returns The constructed ResolvedNode for `packageKey`, or `undefined` if the package cannot be parsed, is not installed, or would create a cycle.
 */
function buildPnpmNode(packageKey, snapshots, index, memo, installState, stack) {
    if (memo.has(packageKey))
        return memo.get(packageKey);
    if (stack.has(packageKey))
        return undefined;
    const parsedKey = parsePnpmPackageKey(packageKey);
    if (!parsedKey)
        return undefined;
    const version = extractVersionFromPnpmRef(parsedKey.ref);
    if (!version)
        return undefined;
    if (!isPnpmPackageInstalled(parsedKey.name, version, installState)) {
        memo.set(packageKey, undefined);
        return undefined;
    }
    const snapshot = snapshots[packageKey] || {};
    const out = {
        name: parsedKey.name,
        version,
        dependencies: {}
    };
    stack.add(packageKey);
    // pnpm snapshots already carry resolved installed deps in `dependencies`/`optionalDependencies`.
    // Do not traverse `peerDependencies` ranges here: they can overwrite resolved child refs
    // (for example `child: ^1.0.0` over `child: 1.0.0`) and incorrectly drop installed nodes.
    const childRefs = mergeStringRecord(snapshot === null || snapshot === void 0 ? void 0 : snapshot.dependencies, snapshot === null || snapshot === void 0 ? void 0 : snapshot.optionalDependencies);
    for (const [childName, childRef] of Object.entries(childRefs)) {
        if (!childRef || isWorkspaceLikeSpecifier(childRef))
            continue;
        const resolved = resolvePnpmDependency(childName, childRef, index);
        if (!resolved)
            continue;
        const childNode = buildPnpmNode(resolved.packageKey, snapshots, index, memo, installState, stack);
        if (!childNode)
            continue;
        out.dependencies[childNode.name] = childNode;
    }
    stack.delete(packageKey);
    if (out.dependencies && Object.keys(out.dependencies).length === 0) {
        delete out.dependencies;
    }
    memo.set(packageKey, out);
    return out;
}
/**
 * Parse a pnpm package key into its package name and reference.
 *
 * @param key - The raw package key from a pnpm lockfile (may be prefixed with '/')
 * @returns An object with `name` and `ref` when `key` follows pnpm's package-key format, `undefined` otherwise.
 */
function parsePnpmPackageKey(key) {
    const normalized = key.startsWith('/') ? key.slice(1) : key;
    if (!normalized)
        return undefined;
    if (normalized.startsWith('@')) {
        const slashIndex = normalized.indexOf('/');
        if (slashIndex < 0)
            return undefined;
        const atIndex = normalized.indexOf('@', slashIndex + 1);
        if (atIndex < 0)
            return undefined;
        const name = normalized.slice(0, atIndex);
        const ref = normalized.slice(atIndex + 1);
        if (!name || !ref)
            return undefined;
        return { name, ref };
    }
    const atIndex = normalized.indexOf('@');
    if (atIndex < 0)
        return undefined;
    const name = normalized.slice(0, atIndex);
    const ref = normalized.slice(atIndex + 1);
    if (!name || !ref)
        return undefined;
    return { name, ref };
}
/**
 * Removes a trailing parenthesized peer-dependency suffix from a pnpm package reference.
 *
 * @param ref - A pnpm package reference that may end with a parenthesized peer suffix (e.g., "pkg@1.2.3 (peer)")
 * @returns The reference with a trailing "(...)" suffix removed, if present
 */
function stripPnpmPeerSuffix(ref) {
    return ref.replace(/\(.+\)$/g, '');
}
/**
 * Extracts a version string from a pnpm package reference.
 *
 * @param ref - Raw pnpm package reference (e.g., `npm:pkg@1.2.3`, `@scope/pkg@1.0.0`, or values with peer-suffixes like `pkg@1.0.0 (peer)`). Workspace-like specifiers (`link:`, `workspace:`, `file:`, `portal:`) may be provided.
 * @returns The version portion of the reference, or an empty string if a version cannot be determined (including when the reference is a workspace-like specifier).
 */
function extractVersionFromPnpmRef(ref) {
    const stripped = stripPnpmPeerSuffix(ref).trim();
    if (!stripped || isWorkspaceLikeSpecifier(stripped))
        return '';
    if (stripped.startsWith('npm:')) {
        const target = stripped.slice(4);
        const at = target.lastIndexOf('@');
        if (at > 0)
            return target.slice(at + 1);
        return target;
    }
    return stripped;
}
/**
 * Extracts a string reference from a pnpm package value.
 *
 * @param value - A pnpm package reference which may be a string or an object containing a `version` field.
 * @returns The trimmed string reference if present, `undefined` otherwise.
 */
function extractPnpmRef(value) {
    if (typeof value === 'string') {
        const trimmed = value.trim();
        return trimmed || undefined;
    }
    if (!value || typeof value !== 'object')
        return undefined;
    const version = value.version;
    if (typeof version === 'string') {
        const trimmed = version.trim();
        return trimmed || undefined;
    }
    return undefined;
}
/**
 * Normalize a pnpm dependency reference into a { name, ref } shape or skip workspace-like/empty refs.
 *
 * @param rawRef - The raw reference string from the lockfile (may be an npm alias like `npm:pkg@1.0.0`, a path, or a workspace-like specifier).
 * @param dependencyName - The dependency name to use when the ref does not provide an explicit package name.
 * @returns The resolved `{ name, ref }` pair with a cleaned `ref`, or `undefined` if `rawRef` is empty or a workspace-like specifier.
 */
function normalizePnpmRef(rawRef, dependencyName) {
    const trimmed = rawRef.trim();
    if (!trimmed || isWorkspaceLikeSpecifier(trimmed))
        return undefined;
    if (!trimmed.startsWith('npm:')) {
        const cleaned = trimmed.startsWith('/') ? trimmed.slice(1) : trimmed;
        return { name: dependencyName, ref: cleaned };
    }
    const target = trimmed.slice(4);
    const parsed = parsePackageAliasTarget(target);
    if (!parsed) {
        return { name: dependencyName, ref: target };
    }
    return parsed;
}
/**
 * Parse a package alias target string (e.g. `pkg@1.2.3` or `@scope/pkg@1.2.3`) into its package name and reference.
 *
 * @param value - The alias target string to parse.
 * @returns An object with `name` (package name or scoped name) and `ref` (the part after the `@`), or `undefined` if `value` is not a valid alias target.
 */
function parsePackageAliasTarget(value) {
    if (!value)
        return undefined;
    if (value.startsWith('@')) {
        const slashIndex = value.indexOf('/');
        if (slashIndex < 0)
            return undefined;
        const atIndex = value.indexOf('@', slashIndex + 1);
        if (atIndex < 0)
            return undefined;
        return {
            name: value.slice(0, atIndex),
            ref: value.slice(atIndex + 1)
        };
    }
    const atIndex = value.lastIndexOf('@');
    if (atIndex <= 0)
        return undefined;
    return {
        name: value.slice(0, atIndex),
        ref: value.slice(atIndex + 1)
    };
}
/**
 * Builds a dependency tree from an npm lockfile found by searching upwards from the project path.
 *
 * Searches for `npm-shrinkwrap.json` or `package-lock.json`. If a lockfile is found and contains a resolvable
 * dependency structure (either a `packages` map or legacy `dependencies`), returns a LockfileTreeResult for that lockfile.
 *
 * @param projectPath - Path inside the project where the search for a lockfile starts
 * @param searchRoot - Directory at which to stop the upward search (optional)
 * @returns A LockfileTreeResult when a suitable npm lockfile and dependency tree are found, `undefined` otherwise
 */
function parseNpmTree(projectPath, searchRoot) {
    const lockPath = findUpwards(projectPath, ['npm-shrinkwrap.json', 'package-lock.json'], searchRoot);
    if (!lockPath)
        return undefined;
    const parsed = getCachedJson(lockPath);
    if (!parsed || typeof parsed !== 'object')
        return undefined;
    if (parsed.packages && typeof parsed.packages === 'object') {
        const data = parseNpmTreeFromPackages(parsed.packages, projectPath, path_1.default.dirname(lockPath));
        if (!data)
            return undefined;
        return { sourceFile: lockPath, data };
    }
    if (parsed.dependencies && typeof parsed.dependencies === 'object') {
        const dependencies = {};
        for (const [depName, node] of Object.entries(parsed.dependencies)) {
            const normalized = normalizeLegacyNpmNode(depName, node);
            if (normalized)
                dependencies[depName] = normalized;
        }
        return { sourceFile: lockPath, data: { dependencies } };
    }
    return undefined;
}
/**
 * Builds a dependency tree from an npm lockfile "packages" map for the specified project.
 *
 * @param packages - The lockfile `packages` map (keys are normalized package paths from package-lock.json or npm-shrinkwrap.json)
 * @param projectPath - The project directory to resolve as the root for dependency collection
 * @param lockDir - The directory containing the lockfile; used to compute the root package key
 * @returns A ResolvedTree mapping root dependency names to resolved nodes, or `undefined` if no valid root entry exists in `packages`
 */
function parseNpmTreeFromPackages(packages, projectPath, lockDir) {
    const installState = createNpmInstallState(projectPath, lockDir);
    const projectRel = toPosixRelative(lockDir, projectPath);
    const rootKey = projectRel === '' ? '' : projectRel;
    if (!(rootKey in packages) && rootKey !== '') {
        return undefined;
    }
    const packageKey = rootKey;
    const rootEntry = packages[packageKey];
    if (!rootEntry || typeof rootEntry !== 'object')
        return undefined;
    const rootDepNames = collectDependencyNames(rootEntry);
    const dependencies = {};
    const memo = new Map();
    const stack = new Set();
    for (const depName of rootDepNames) {
        const childKey = resolveNpmPackagePath(packageKey, depName, packages);
        if (!childKey)
            continue;
        const childNode = buildNpmNodeFromPackages(childKey, depName, packages, memo, stack, installState);
        if (childNode)
            dependencies[childNode.name] = childNode;
    }
    return { dependencies };
}
/**
 * Builds a ResolvedNode for an npm lockfile package entry.
 *
 * @param packageKey - Normalized key identifying the package entry within the lockfile `packages` map.
 * @param fallbackName - Package name to use when the entry does not provide a valid `name` field.
 * @param packages - The lockfile `packages` map containing package entry objects indexed by package keys.
 * @param memo - Memoization map used to cache previously built nodes (or `undefined` for unresolved entries).
 * @param stack - Recursion stack used to detect and avoid cycles while building the dependency graph.
 * @returns The constructed `ResolvedNode` for `packageKey`, or `undefined` if the entry is missing, invalid, cyclic, or cannot be resolved.
 */
function buildNpmNodeFromPackages(packageKey, fallbackName, packages, memo, stack, installState) {
    if (memo.has(packageKey))
        return memo.get(packageKey);
    if (stack.has(packageKey))
        return undefined;
    if (!isNpmPackageInstalled(packageKey, installState)) {
        memo.set(packageKey, undefined);
        return undefined;
    }
    const entry = packages[packageKey];
    if (!entry || typeof entry !== 'object')
        return undefined;
    if (entry.link === true && typeof entry.resolved === 'string') {
        const linkedKey = normalizeLockPackageKey(entry.resolved);
        if (linkedKey && linkedKey in packages) {
            const linkedNode = buildNpmNodeFromPackages(linkedKey, fallbackName, packages, memo, stack, installState);
            memo.set(packageKey, linkedNode);
            return linkedNode;
        }
    }
    const version = typeof entry.version === 'string' ? entry.version.trim() : '';
    if (!version || version === 'unknown' || version === 'missing' || version === 'invalid') {
        memo.set(packageKey, undefined);
        return undefined;
    }
    const name = typeof entry.name === 'string' && entry.name.trim() ? entry.name.trim() : fallbackName;
    const out = {
        name,
        version,
        dependencies: {}
    };
    const packagePath = resolveNpmInstalledPath(packageKey, installState.lockDir);
    if (packagePath) {
        out.path = packagePath;
    }
    if ((entry === null || entry === void 0 ? void 0 : entry.dev) !== undefined) {
        out.dev = Boolean(entry.dev);
    }
    stack.add(packageKey);
    const depNames = collectDependencyNames(entry);
    for (const depName of depNames) {
        const childKey = resolveNpmPackagePath(packageKey, depName, packages);
        if (!childKey)
            continue;
        const childNode = buildNpmNodeFromPackages(childKey, depName, packages, memo, stack, installState);
        if (!childNode)
            continue;
        out.dependencies[childNode.name] = childNode;
    }
    stack.delete(packageKey);
    if (out.dependencies && Object.keys(out.dependencies).length === 0) {
        delete out.dependencies;
    }
    memo.set(packageKey, out);
    return out;
}
/**
 * Normalize a lockfile package key into a POSIX-style relative path.
 *
 * @param value - The raw package key or path from a lockfile
 * @returns The normalized package key with any leading "./" or "/" removed, path separators converted to `/`, or an empty string if `value` is empty or whitespace
 */
function normalizeLockPackageKey(value) {
    const trimmed = value.trim();
    if (!trimmed)
        return '';
    return trimmed.replace(/^\.?\//, '').split(path_1.default.sep).join('/');
}
/**
 * Resolve the lockfile packages map key for a dependency by searching node_modules upward from a starting package path.
 *
 * Searches for "<fromPackageKey>/node_modules/<depName>" and climbs parent directories until the repository root,
 * then falls back to "node_modules/<depName>".
 *
 * @param fromPackageKey - The package key/path in the lockfile packages map to start from (posix-style, may be empty)
 * @param depName - The dependency name to resolve
 * @param packages - The lockfile `packages` map (keys are package paths)
 * @returns The matching package key (e.g. "node_modules/dep" or "some/dir/node_modules/dep") if found, `undefined` otherwise
 */
function resolveNpmPackagePath(fromPackageKey, depName, packages) {
    const from = fromPackageKey || '';
    let dir = from;
    while (true) {
        const candidate = dir ? `${dir}/node_modules/${depName}` : `node_modules/${depName}`;
        if (candidate in packages)
            return candidate;
        if (!dir)
            break;
        const parent = path_1.default.posix.dirname(dir);
        dir = parent === '.' ? '' : parent;
    }
    const rootCandidate = `node_modules/${depName}`;
    return rootCandidate in packages ? rootCandidate : undefined;
}
/**
 * Resolve an npm lockfile package key to the absolute filesystem path where that package would be installed under a given lock directory.
 *
 * @param packageKey - The package key from a lockfile (e.g., a normalized/package-relative path or package identifier).
 * @param lockDir - The lockfile directory to treat as the installation root.
 * @returns The absolute path inside `lockDir` corresponding to `packageKey` if it resolves to a location contained within `lockDir`, `undefined` otherwise.
 */
function resolveNpmInstalledPath(packageKey, lockDir) {
    const normalizedKey = normalizeLockPackageKey(packageKey);
    if (!normalizedKey)
        return undefined;
    const segments = normalizedKey.split('/').filter(Boolean);
    if (segments.length === 0)
        return undefined;
    for (const segment of segments) {
        if (segment === '.' || segment === '..')
            return undefined;
        if (path_1.default.isAbsolute(segment))
            return undefined;
    }
    const lockRoot = path_1.default.resolve(lockDir);
    const resolved = path_1.default.resolve(lockRoot, ...segments);
    const relative = path_1.default.relative(lockRoot, resolved);
    if (relative.startsWith('..') || path_1.default.isAbsolute(relative))
        return undefined;
    return resolved;
}
/**
 * Normalize a legacy npm lockfile node into a ResolvedNode.
 *
 * Recursively converts a legacy lockfile node structure into the module's ResolvedNode shape,
 * preserving the package name, validated version, transitive dependencies, and the dev flag.
 *
 * @param name - The dependency name as declared in the lockfile
 * @param node - The legacy lockfile node object to normalize (may contain version, dependencies, dev, missing, extraneous)
 * @returns A ResolvedNode for the package, or `undefined` if the input node is missing, extraneous, or has an invalid/unknown/missing version
 */
function normalizeLegacyNpmNode(name, node) {
    if (!node || typeof node !== 'object')
        return undefined;
    if (node.missing || node.extraneous)
        return undefined;
    const version = typeof node.version === 'string' ? node.version.trim() : '';
    if (!version || version === 'unknown' || version === 'missing' || version === 'invalid')
        return undefined;
    const out = {
        name,
        version,
        dependencies: {}
    };
    if ((node === null || node === void 0 ? void 0 : node.dependencies) && typeof node.dependencies === 'object') {
        for (const [childName, child] of Object.entries(node.dependencies)) {
            const normalized = normalizeLegacyNpmNode(childName, child);
            if (normalized)
                out.dependencies[childName] = normalized;
        }
    }
    if ((node === null || node === void 0 ? void 0 : node.dev) !== undefined) {
        out.dev = Boolean(node.dev);
    }
    if (out.dependencies && Object.keys(out.dependencies).length === 0) {
        delete out.dependencies;
    }
    return out;
}
/**
 * Builds a resolved dependency tree from a Yarn lockfile for the given project.
 *
 * Searches upward for a yarn.lock from the provided project path (stopping at `searchRoot`), ensures the project's package.json is present and readable, parses the lockfile as Yarn v1 or v2, and constructs a LockfileTreeResult.
 *
 * @param projectPath - The project directory containing package.json used as the resolution root
 * @param searchRoot - Directory at which to stop searching upward for a yarn.lock
 * @returns A LockfileTreeResult with `sourceFile` set to the located yarn.lock and `data` containing the resolved dependency tree, or `undefined` if the lockfile or package.json cannot be found or parsed
 */
function parseYarnTree(projectPath, searchRoot) {
    const lockPath = findUpwards(projectPath, ['yarn.lock'], searchRoot);
    if (!lockPath)
        return undefined;
    const raw = readCachedText(lockPath);
    if (!raw)
        return undefined;
    const packageJsonPath = path_1.default.join(projectPath, 'package.json');
    if (!safePathExists(packageJsonPath))
        return undefined;
    const packageJson = readJsonSafe(packageJsonPath);
    if (!packageJson || typeof packageJson !== 'object')
        return undefined;
    if (/^#\s*yarn lockfile v1/m.test(raw)) {
        const parsed = parseYarnV1(raw);
        if (!parsed)
            return undefined;
        const data = buildYarnResolvedTree(parsed, packageJson);
        return { sourceFile: lockPath, data };
    }
    const parsedYaml = parseYarnV2(raw);
    if (!parsedYaml)
        return undefined;
    const data = buildYarnResolvedTree(parsedYaml, packageJson);
    return { sourceFile: lockPath, data };
}
/**
 * Parse a Yarn v1 lockfile string into a selector-to-entry map.
 *
 * @param raw - The raw contents of a yarn.lock file (Yarn v1 format)
 * @returns A Map where each selector string maps to its YarnV1Entry, or `undefined` if parsing fails or the lockfile is not a Yarn v1 success parse
 */
function parseYarnV1(raw) {
    return (0, lockfileParsers_1.parseYarnV1Lockfile)(raw);
}
/**
 * Parse a Yarn v2 (Berry) lockfile YAML string into a selector-to-entry map.
 *
 * @param raw - Raw contents of a yarn.lock (Yarn v2+) file
 * @returns A Map where each lockfile selector maps to its YarnV2Entry, or `undefined` if the input could not be parsed into an object
 */
function parseYarnV2(raw) {
    const parsed = (0, lockfileParsers_1.parseYamlLike)(raw);
    if (!parsed || typeof parsed !== 'object')
        return undefined;
    const map = new Map();
    for (const [selectorKey, entry] of Object.entries(parsed)) {
        if (selectorKey === '__metadata')
            continue;
        if (!entry || typeof entry !== 'object')
            continue;
        for (const selector of splitSelectors(selectorKey)) {
            if (!map.has(selector)) {
                map.set(selector, entry);
            }
        }
    }
    return map;
}
/**
 * Build a resolved dependency tree from Yarn lockfile entries and a project package.json.
 *
 * Uses the package.json dependency sections to find root dependency ranges, resolves each range
 * against the provided Yarn lock entries, and constructs a map of resolved package nodes.
 *
 * @param lockEntries - Map of selector keys to Yarn v1 or v2 lockfile entries used to resolve selectors.
 * @param packageJson - The project's parsed package.json object whose dependency sections are consulted.
 * @returns A ResolvedTree whose `dependencies` map contains resolved top-level ResolvedNode objects; workspace-like specifiers and unresolved selectors are omitted.
 */
function buildYarnResolvedTree(lockEntries, packageJson) {
    const memo = new Map();
    const stack = new Set();
    const dependencies = {};
    const rootDeps = collectPackageJsonDependencySpecs(packageJson);
    for (const [depName, depRange] of Object.entries(rootDeps)) {
        if (isWorkspaceLikeSpecifier(depRange))
            continue;
        const selector = resolveYarnSelector(depName, depRange, lockEntries);
        if (!selector)
            continue;
        const node = buildYarnNode(depName, selector, lockEntries, memo, stack);
        if (node)
            dependencies[node.name] = node;
    }
    return { dependencies };
}
/**
 * Resolve a Yarn lockfile entry into a ResolvedNode, including its child dependencies.
 *
 * Builds a normalized ResolvedNode for the package identified by `name` and `selector` from `lockEntries`.
 * Skips workspace-like specs and invalid/missing versions. Uses `memo` to cache results and `stack` to
 * detect and avoid cycles during recursive resolution.
 *
 * @param name - The dependency name to resolve
 * @param selector - The lockfile selector/key that identifies the specific locked entry
 * @param lockEntries - Map of lockfile selectors to Yarn lock entries (v1 or v2)
 * @param memo - Memoization map used to cache previously resolved nodes or unresolved results
 * @param stack - Set tracking the current recursion path to prevent cycles
 * @returns `ResolvedNode` for the resolved dependency, or `undefined` if the entry cannot be resolved or is invalid
 */
function buildYarnNode(name, selector, lockEntries, memo, stack) {
    const memoKey = `${name}|${selector}`;
    if (memo.has(memoKey))
        return memo.get(memoKey);
    if (stack.has(memoKey))
        return undefined;
    const entry = lockEntries.get(selector);
    if (!entry || typeof entry !== 'object')
        return undefined;
    const version = typeof entry.version === 'string' ? entry.version.trim() : '';
    if (!version || version === 'unknown' || version === 'missing' || version === 'invalid') {
        memo.set(memoKey, undefined);
        return undefined;
    }
    const out = {
        name,
        version,
        dependencies: {}
    };
    stack.add(memoKey);
    const childDeps = mergeStringRecord(entry.dependencies, entry.optionalDependencies);
    for (const [depName, depRange] of Object.entries(childDeps)) {
        if (!depRange || isWorkspaceLikeSpecifier(depRange))
            continue;
        const childSelector = resolveYarnSelector(depName, depRange, lockEntries);
        if (!childSelector)
            continue;
        const childNode = buildYarnNode(depName, childSelector, lockEntries, memo, stack);
        if (!childNode)
            continue;
        out.dependencies[childNode.name] = childNode;
    }
    stack.delete(memoKey);
    if (out.dependencies && Object.keys(out.dependencies).length === 0) {
        delete out.dependencies;
    }
    memo.set(memoKey, out);
    return out;
}
/**
 * Resolve a Yarn lockfile selector key that corresponds to a dependency name and range.
 *
 * Attempts to match exact selector forms (including `npm:`-prefixed variants), then falls back
 * to selectors that start with `name@` and contain the range; if multiple fallback matches
 * exist the lexicographically first is chosen.
 *
 * @param dependencyName - The dependency package name
 * @param dependencyRange - The version range or specifier (may be prefixed with `npm:`)
 * @param lockEntries - Map of lockfile selector keys to their entries
 * @returns A lockfile selector key that matches the dependency, or `undefined` if none found
 */
function resolveYarnSelector(dependencyName, dependencyRange, lockEntries) {
    const trimmedRange = dependencyRange.trim();
    const candidates = new Set([
        `${dependencyName}@${trimmedRange}`,
        `${dependencyName}@npm:${trimmedRange}`
    ]);
    if (trimmedRange.startsWith('npm:')) {
        candidates.add(`${dependencyName}@${trimmedRange.slice(4)}`);
    }
    for (const candidate of candidates) {
        if (lockEntries.has(candidate))
            return candidate;
    }
    const prefix = `${dependencyName}@`;
    const fallback = [];
    for (const selector of lockEntries.keys()) {
        if (!selector.startsWith(prefix))
            continue;
        if (selector.includes(trimmedRange)) {
            fallback.push(selector);
        }
    }
    if (fallback.length === 1)
        return fallback[0];
    if (fallback.length > 1) {
        return fallback.sort()[0];
    }
    return undefined;
}
/**
 * Extracts all dependency specifiers declared in a package.json-like object.
 *
 * Aggregates entries from "dependencies", "devDependencies", "optionalDependencies", and "peerDependencies".
 *
 * @param pkg - The parsed package.json object to read dependency sections from
 * @returns A map of dependency name to its version or range string for every declared dependency
 */
function collectPackageJsonDependencySpecs(pkg) {
    const out = {};
    for (const sectionName of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        const section = pkg === null || pkg === void 0 ? void 0 : pkg[sectionName];
        if (!section || typeof section !== 'object')
            continue;
        for (const [name, spec] of Object.entries(section)) {
            if (typeof spec !== 'string')
                continue;
            out[name] = spec;
        }
    }
    return out;
}
/**
 * Split a Yarn selector key into individual selector strings.
 *
 * @param selectorKey - A comma-separated selector string from a lockfile entry
 * @returns An array of trimmed, non-empty selector strings
 */
function splitSelectors(selectorKey) {
    return (0, lockfileParsers_1.splitSelectorList)(selectorKey);
}
/**
 * Merge two arbitrary values into a string-to-string record, with entries from the second overriding the first.
 *
 * Non-object values are ignored; only own enumerable properties whose values are strings are included.
 *
 * @param first - Source whose string-valued properties are copied first
 * @param second - Source whose string-valued properties override those from `first`
 * @returns A record mapping property names to their string values collected from `first` and `second`
 */
function mergeStringRecord(first, second) {
    const out = {};
    const assign = (value) => {
        if (!value || typeof value !== 'object')
            return;
        for (const [key, val] of Object.entries(value)) {
            if (typeof val === 'string') {
                out[key] = val;
            }
        }
    };
    assign(first);
    assign(second);
    return out;
}
/**
 * Collects all dependency names referenced by a lockfile or package entry.
 *
 * @param entry - An object that may contain dependency sections (`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`)
 * @returns An array of unique dependency names aggregated from the entry's dependency sections
 */
function collectDependencyNames(entry) {
    const names = new Set();
    for (const sectionName of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        const section = entry === null || entry === void 0 ? void 0 : entry[sectionName];
        if (!section || typeof section !== 'object')
            continue;
        for (const name of Object.keys(section)) {
            names.add(name);
        }
    }
    return Array.from(names);
}
/**
 * Check if a dependency specifier refers to a workspace or local reference.
 *
 * @param value - The dependency specifier to test (e.g., "file:../pkg", "workspace:^1.0.0")
 * @returns `true` if the specifier starts with `link:`, `workspace:`, `file:`, or `portal:`, `false` otherwise.
 */
function isWorkspaceLikeSpecifier(value) {
    const trimmed = value.trim();
    return (trimmed.startsWith('link:') ||
        trimmed.startsWith('workspace:') ||
        trimmed.startsWith('file:') ||
        trimmed.startsWith('portal:'));
}
/**
 * Search upward from a starting directory for any of the given filenames and return the first match.
 *
 * @param startPath - Directory path to begin the upward search from
 * @param fileNames - List of filenames to look for in each directory
 * @param stopPath - Directory path at which to stop searching (inclusive)
 * @returns The resolved path to the first matching file found, or `undefined` if none is found before `stopPath`
 */
function findUpwards(startPath, fileNames, stopPath) {
    const stop = path_1.default.resolve(stopPath);
    let current = path_1.default.resolve(startPath);
    while (true) {
        for (const fileName of fileNames) {
            const candidate = path_1.default.join(current, fileName);
            if (safePathExists(candidate)) {
                return candidate;
            }
        }
        if (current === stop) {
            return undefined;
        }
        const parent = path_1.default.dirname(current);
        if (parent === current)
            return undefined;
        current = parent;
    }
}
/**
 * Compute the POSIX-style relative path from one filesystem path to another.
 *
 * @param fromPath - The base path to resolve from
 * @param toPath - The target path to resolve to
 * @returns The relative path using forward slashes (`/`), or an empty string when the target is the same as the base
 */
function toPosixRelative(fromPath, toPath) {
    const relative = path_1.default.relative(fromPath, toPath);
    if (!relative || relative === '.')
        return '';
    return relative.split(path_1.default.sep).join('/');
}
/**
 * Checks whether a filesystem path exists and is accessible, returning false on any error.
 *
 * @param targetPath - The filesystem path to check
 * @returns `true` if the path exists and is accessible, `false` otherwise.
 */
function safePathExists(targetPath) {
    try {
        return fs_1.default.existsSync(targetPath);
    }
    catch {
        return false;
    }
}
/**
 * Read a text file and cache its contents in memory.
 *
 * @param filePath - Path to the file to read
 * @returns The file contents decoded as UTF-8, or `undefined` if the file cannot be read
 */
function readCachedText(filePath) {
    if (parseCache.has(filePath)) {
        const cached = parseCache.get(filePath);
        return typeof cached === 'string' ? cached : undefined;
    }
    try {
        const raw = fs_1.default.readFileSync(filePath, 'utf8');
        parseCache.set(filePath, raw);
        return raw;
    }
    catch {
        return undefined;
    }
}
/**
 * Read and cache the parsed JSON content of a file.
 *
 * @param filePath - Path to the JSON file
 * @returns The parsed JSON value, or `undefined` if the file cannot be read
 * @throws SyntaxError if the file is read but contains invalid JSON
 */
function getCachedJson(filePath) {
    const cacheKey = `${filePath}:json`;
    if (parseCache.has(cacheKey))
        return parseCache.get(cacheKey);
    const raw = readCachedText(filePath);
    if (!raw)
        return undefined;
    const parsed = JSON.parse(raw);
    parseCache.set(cacheKey, parsed);
    return parsed;
}
/**
 * Parse YAML content from the given file path and cache the result for subsequent calls.
 *
 * @param filePath - Path to the YAML file to read and parse
 * @returns The parsed YAML value, or `undefined` if the file could not be read or is empty
 */
function getCachedYaml(filePath) {
    const cacheKey = `${filePath}:yaml`;
    if (parseCache.has(cacheKey))
        return parseCache.get(cacheKey);
    const raw = readCachedText(filePath);
    if (!raw)
        return undefined;
    const parsed = (0, lockfileParsers_1.parseYamlLike)(raw);
    parseCache.set(cacheKey, parsed);
    return parsed;
}
/**
 * Read and parse a JSON file, returning its contents or undefined on failure.
 *
 * @param filePath - Path to the JSON file to read
 * @returns The parsed JSON value, or `undefined` if the file cannot be read or parsed
 */
function readJsonSafe(filePath) {
    try {
        const raw = fs_1.default.readFileSync(filePath, 'utf8');
        return JSON.parse(raw);
    }
    catch {
        return undefined;
    }
}
/**
 * Create a pnpm installation state by discovering node_modules roots and .pnpm virtual store entries for a project path.
 *
 * @param projectPath - Filesystem path inside the project to start discovery from
 * @returns An object containing:
 *  - `enabled`: `true` if any virtual store entries or node_modules roots were found, `false` otherwise;
 *  - `virtualStoreEntries`: a set of directory names found under each discovered `.pnpm` folder;
 *  - `nodeModulesRoots`: array of discovered `node_modules` root paths;
 *  - `installedCache`: an initially empty cache map for package installation checks
 */
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
/**
 * Create npm installation state used to filter lockfile package entries to actually installed paths.
 *
 * @param projectPath - Filesystem path inside the project to start discovery from
 * @param lockDir - Directory containing the npm lockfile
 * @returns Installation state with detected node_modules roots and per-package-key cache
 */
function createNpmInstallState(projectPath, lockDir) {
    const nodeModulesRoots = findNodeModulesRoots(projectPath);
    return {
        enabled: nodeModulesRoots.length > 0,
        lockDir,
        installedByKeyCache: new Map()
    };
}
/**
 * Discover node_modules directories by walking upward from a starting path.
 *
 * @param startPath - Path to begin the upward search from.
 * @returns An array of absolute paths to `node_modules` directories found while traversing upward, ordered from nearest to farthest.
 */
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
/**
 * Determine whether a package-lock `packages` entry key points to an installed package path.
 *
 * @param packageKey - Key from package-lock `packages` map
 * @param installState - npm installation state with lockDir and cache
 * @returns `true` when the key should be considered installed, `false` otherwise
 */
function isNpmPackageInstalled(packageKey, installState) {
    if (!installState.enabled)
        return true;
    const normalizedKey = normalizeLockPackageKey(packageKey);
    if (!normalizedKey)
        return true;
    const cached = installState.installedByKeyCache.get(normalizedKey);
    if (cached !== undefined)
        return cached;
    const candidate = path_1.default.join(installState.lockDir, ...normalizedKey.split('/'));
    const installed = safePathExists(candidate);
    installState.installedByKeyCache.set(normalizedKey, installed);
    return installed;
}
/**
 * Read the names of entries in a directory, returning an empty array if the directory cannot be read.
 *
 * @param dirPath - Path to the directory to read
 * @returns An array of directory entry names, or an empty array if the directory does not exist or cannot be read
 */
function safeReadDirNames(dirPath) {
    try {
        return fs_1.default.readdirSync(dirPath);
    }
    catch {
        return [];
    }
}
/**
 * Determine whether a pnpm package with the given name and version is considered installed according to the provided pnpm install state.
 *
 * Looks up the package in the pnpm virtual store entries and in discovered node_modules roots. Results are cached on `installState.installedCache`.
 *
 * @param name - Package name (may be scoped)
 * @param version - Expected package version
 * @param installState - pnpm installation state used to inspect virtual store entries and node_modules roots
 * @returns `true` if the package is considered installed (found in the pnpm virtual store or node_modules and matching the version), `false` otherwise.
 */
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
/**
 * Convert a scoped package name into the pnpm store form by replacing the scope/name slash with a plus.
 *
 * @param name - Package name, possibly scoped (for example, "@scope/pkg")
 * @returns The pnpm-store form (for example, "@scope+pkg"); returns the original `name` if it is not a valid scoped package
 */
function normalizeScopedPackageNameForPnpmStore(name) {
    if (!name.startsWith('@'))
        return name;
    const slashIndex = name.indexOf('/');
    if (slashIndex <= 0)
        return name;
    return `${name.slice(0, slashIndex)}+${name.slice(slashIndex + 1)}`;
}
/**
 * Checks whether a package directory's declared version matches an expected version.
 *
 * Treats a missing or unreadable package.json, or a package.json without a `version` field, as matching.
 *
 * @param packageDir - Path to the package directory containing a package.json
 * @param expectedVersion - The version string to compare against the package's declared version
 * @returns `true` if the package.json is missing/unreadable, lacks a `version`, or its `version` equals `expectedVersion`; `false` otherwise
 */
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
