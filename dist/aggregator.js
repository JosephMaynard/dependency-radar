"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.aggregateData = aggregateData;
const utils_1 = require("./utils");
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const crypto_1 = __importDefault(require("crypto"));
const dependencyRadarVersion = (0, utils_1.getDependencyRadarVersion)();
async function getGitBranch(projectPath) {
    var _a;
    try {
        const result = await (0, utils_1.runCommand)('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: projectPath });
        const branch = (_a = result.stdout) === null || _a === void 0 ? void 0 : _a.trim();
        // HEAD means detached state
        if (!branch || branch === 'HEAD') {
            return undefined;
        }
        return branch;
    }
    catch {
        return undefined;
    }
}
function findRootCauses(node, nodeMap, pkg) {
    // If it's a direct dependency, it's its own root cause
    if (isDirectDependency(node.name, pkg)) {
        return [node.name];
    }
    // BFS up the parent chain to find all direct dependencies that lead to this
    const rootCauses = new Set();
    const visited = new Set();
    const queue = [...node.parents];
    while (queue.length > 0) {
        const parentKey = queue.shift();
        if (visited.has(parentKey))
            continue;
        visited.add(parentKey);
        const parent = nodeMap.get(parentKey);
        if (!parent)
            continue;
        if (isDirectDependency(parent.name, pkg)) {
            rootCauses.add(parent.name);
        }
        else {
            // Keep going up the chain
            for (const grandparent of parent.parents) {
                if (!visited.has(grandparent)) {
                    queue.push(grandparent);
                }
            }
        }
    }
    return Array.from(rootCauses).sort();
}
function hashProjectPath(projectPath) {
    return crypto_1.default.createHash('sha256').update(projectPath).digest('hex');
}
async function aggregateData(input) {
    var _a, _b, _c;
    const pkg = input.pkgOverride || (await (0, utils_1.readPackageJson)(input.projectPath));
    // Get git branch
    const gitBranch = await getGitBranch(input.projectPath);
    const nodeMap = buildNodeMap((_a = input.npmLsResult) === null || _a === void 0 ? void 0 : _a.data, pkg);
    const vulnMap = parseVulnerabilities((_b = input.auditResult) === null || _b === void 0 ? void 0 : _b.data);
    const packageMetaCache = new Map();
    const packageStatCache = new Map();
    const dependencies = {};
    const licenseCache = new Map();
    const nodeEngineRanges = [];
    const nodes = Array.from(nodeMap.values());
    let directCount = 0;
    const MAX_TOP_ROOT_PACKAGES = 10; // cap to keep payload size predictable
    for (const node of nodes) {
        const direct = isDirectDependency(node.name, pkg);
        if (direct)
            directCount += 1;
        const cachedLicense = licenseCache.get(node.name);
        const license = cachedLicense ||
            (await (0, utils_1.readLicenseFromPackageJson)(node.name, input.projectPath)) ||
            { license: undefined };
        if (!licenseCache.has(node.name) && license.license) {
            licenseCache.set(node.name, license);
        }
        const vulnerabilities = vulnMap.get(node.name) || emptyVulnSummary();
        const licenseValue = license.license || 'unknown';
        const licenseRisk = (0, utils_1.licenseRiskLevel)(licenseValue);
        const vulnRisk = (0, utils_1.vulnRiskLevel)(vulnerabilities.counts);
        // Calculate root causes (direct dependencies that cause this to be installed)
        const rootCauses = findRootCauses(node, nodeMap, pkg);
        const packageInsights = await gatherPackageInsights(node.name, input.projectPath, packageMetaCache, packageStatCache);
        if (packageInsights.nodeEngine) {
            nodeEngineRanges.push(packageInsights.nodeEngine);
        }
        const scope = determineScope(node.name, direct, rootCauses, pkg);
        const origins = buildOrigins(rootCauses, (_c = input.workspaceUsage) === null || _c === void 0 ? void 0 : _c.get(node.name), input.workspaceEnabled, MAX_TOP_ROOT_PACKAGES);
        const buildRisk = determineBuildRisk(packageInsights.build.native, packageInsights.build.installScripts);
        const id = node.key;
        dependencies[id] = {
            id,
            name: node.name,
            version: node.version,
            direct,
            scope,
            depth: node.depth,
            origins,
            license: licenseValue,
            licenseRisk,
            vulnerabilities: {
                critical: vulnerabilities.counts.critical,
                high: vulnerabilities.counts.high,
                moderate: vulnerabilities.counts.moderate,
                low: vulnerabilities.counts.low,
                highest: vulnerabilities.highestSeverity
            },
            vulnRisk,
            deprecated: packageInsights.deprecated,
            nodeEngine: packageInsights.nodeEngine,
            build: {
                native: packageInsights.build.native,
                installScripts: packageInsights.build.installScripts,
                risk: buildRisk
            },
            tsTypes: packageInsights.tsTypes,
            dependencySurface: packageInsights.dependencySurface,
            graph: {
                fanIn: node.parents.size,
                fanOut: node.children.size
            },
            links: {
                npm: `https://www.npmjs.com/package/${node.name}`
            }
        };
    }
    const minRequiredMajor = deriveMinRequiredMajor(nodeEngineRanges);
    const runtimeVersion = process.version;
    const nodeVersion = process.versions.node;
    const dependencyCount = nodes.length;
    const transitiveCount = dependencyCount - directCount;
    return {
        schemaVersion: '1.0',
        generatedAt: new Date().toISOString(),
        dependencyRadarVersion,
        git: {
            branch: gitBranch || ''
        },
        project: {
            projectDir: input.projectPath,
            projectPathHash: hashProjectPath(input.projectPath)
        },
        environment: {
            nodeVersion,
            runtimeVersion,
            minRequiredMajor: minRequiredMajor !== null && minRequiredMajor !== void 0 ? minRequiredMajor : 0
        },
        workspaces: {
            enabled: input.workspaceEnabled
        },
        summary: {
            dependencyCount,
            directCount,
            transitiveCount
        },
        dependencies
    };
}
function deriveMinRequiredMajor(engineRanges) {
    let strictest;
    for (const range of engineRanges) {
        const minMajor = parseMinMajorFromRange(range);
        if (minMajor === undefined)
            continue;
        if (strictest === undefined || minMajor > strictest) {
            strictest = minMajor;
        }
    }
    return strictest;
}
function parseMinMajorFromRange(range) {
    const normalized = range.trim();
    if (!normalized)
        return undefined;
    const clauses = normalized.split('||').map((clause) => clause.trim()).filter(Boolean);
    if (clauses.length === 0)
        return undefined;
    let rangeMin;
    for (const clause of clauses) {
        const clauseMin = parseMinMajorFromClause(clause);
        // Conservative: skip ranges that allow any version in at least one clause.
        if (clauseMin === undefined)
            return undefined;
        if (rangeMin === undefined || clauseMin < rangeMin) {
            rangeMin = clauseMin;
        }
    }
    return rangeMin;
}
function parseMinMajorFromClause(clause) {
    const hyphenMatch = clause.match(/(\d+)\s*-\s*\d+/);
    if (hyphenMatch) {
        return Number.parseInt(hyphenMatch[1], 10);
    }
    const tokens = clause.replace(/,/g, ' ').split(/\s+/).filter(Boolean);
    let clauseMin;
    for (const token of tokens) {
        if (token.startsWith('<'))
            continue;
        const major = parseMajorFromToken(token);
        if (major === undefined)
            continue;
        if (clauseMin === undefined || major > clauseMin) {
            clauseMin = major;
        }
    }
    return clauseMin;
}
function parseMajorFromToken(token) {
    const trimmed = token.trim();
    if (!trimmed)
        return undefined;
    if (!/^[0-9^~=>v]/.test(trimmed))
        return undefined;
    const match = trimmed.match(/v?(\d+)/);
    if (!match)
        return undefined;
    const major = Number.parseInt(match[1], 10);
    return Number.isNaN(major) ? undefined : major;
}
function buildNodeMap(lsData, pkg) {
    const map = new Map();
    const traverse = (node, depth, parentKey, providedName) => {
        const nodeName = (node === null || node === void 0 ? void 0 : node.name) || providedName;
        if (!node || !nodeName)
            return;
        const version = node.version || 'unknown';
        const key = `${nodeName}@${version}`;
        if (!map.has(key)) {
            map.set(key, {
                name: nodeName,
                version,
                key,
                depth,
                parents: new Set(parentKey ? [parentKey] : []),
                children: new Set(),
                dev: node.dev
            });
        }
        else {
            const existing = map.get(key);
            existing.depth = Math.min(existing.depth, depth);
            if (parentKey)
                existing.parents.add(parentKey);
            if (existing.dev === undefined && node.dev !== undefined)
                existing.dev = node.dev;
            if (!existing.children)
                existing.children = new Set();
        }
        if (node.dependencies && typeof node.dependencies === 'object') {
            Object.entries(node.dependencies).forEach(([depName, child]) => {
                const childVersion = (child === null || child === void 0 ? void 0 : child.version) || 'unknown';
                const childKey = `${depName}@${childVersion}`;
                const current = map.get(key);
                if (current) {
                    current.children.add(childKey);
                }
                traverse(child, depth + 1, key, depName);
            });
        }
    };
    if (lsData && lsData.dependencies) {
        Object.entries(lsData.dependencies).forEach(([depName, child]) => traverse(child, 1, undefined, depName));
    }
    else {
        const deps = Object.keys(pkg.dependencies || {});
        const devDeps = Object.keys(pkg.devDependencies || {});
        deps.forEach((name) => {
            const version = pkg.dependencies[name];
            const key = `${name}@${version}`;
            map.set(key, { name, version, key, depth: 1, parents: new Set(), children: new Set(), dev: false });
        });
        devDeps.forEach((name) => {
            const version = pkg.devDependencies[name];
            const key = `${name}@${version}`;
            map.set(key, { name, version, key, depth: 1, parents: new Set(), children: new Set(), dev: true });
        });
    }
    return map;
}
function parseVulnerabilities(auditData) {
    const map = new Map();
    if (!auditData)
        return map;
    const ensureEntry = (name) => {
        if (!map.has(name)) {
            map.set(name, emptyVulnSummary());
        }
        return map.get(name);
    };
    if (auditData.vulnerabilities) {
        Object.values(auditData.vulnerabilities).forEach((item) => {
            const name = item.name || 'unknown';
            const severity = normalizeSeverity(item.severity);
            const entry = ensureEntry(name);
            entry.counts[severity] = (entry.counts[severity] || 0) + 1;
            const viaList = Array.isArray(item.via) ? item.via : [];
            viaList
                .filter((v) => typeof v === 'object')
                .forEach((vul) => {
                const sev = normalizeSeverity(vul.severity) || severity;
                entry.counts[sev] = (entry.counts[sev] || 0) + 0;
            });
            entry.highestSeverity = computeHighestSeverity(entry.counts);
        });
    }
    if (auditData.advisories) {
        Object.values(auditData.advisories).forEach((adv) => {
            const name = adv.module_name || adv.module || 'unknown';
            const severity = normalizeSeverity(adv.severity);
            const entry = ensureEntry(name);
            entry.counts[severity] = (entry.counts[severity] || 0) + 1;
            entry.highestSeverity = computeHighestSeverity(entry.counts);
        });
    }
    map.forEach((entry) => {
        entry.highestSeverity = computeHighestSeverity(entry.counts);
    });
    return map;
}
function normalizeSeverity(sev) {
    const s = typeof sev === 'string' ? sev.toLowerCase() : 'low';
    if (s === 'moderate')
        return 'moderate';
    if (s === 'high')
        return 'high';
    if (s === 'critical')
        return 'critical';
    return 'low';
}
function emptyVulnSummary() {
    return {
        counts: { low: 0, moderate: 0, high: 0, critical: 0 },
        highestSeverity: 'none'
    };
}
function computeHighestSeverity(counts) {
    if (counts.critical > 0)
        return 'critical';
    if (counts.high > 0)
        return 'high';
    if (counts.moderate > 0)
        return 'moderate';
    if (counts.low > 0)
        return 'low';
    return 'none';
}
function isDirectDependency(name, pkg) {
    return Boolean((pkg.dependencies && pkg.dependencies[name]) || (pkg.devDependencies && pkg.devDependencies[name]));
}
function directScopeFromPackage(name, pkg) {
    if (pkg.dependencies && pkg.dependencies[name])
        return 'runtime';
    if (pkg.devDependencies && pkg.devDependencies[name])
        return 'dev';
    if (pkg.optionalDependencies && pkg.optionalDependencies[name])
        return 'optional';
    if (pkg.peerDependencies && pkg.peerDependencies[name])
        return 'peer';
    return undefined;
}
function determineScope(name, direct, rootCauses, pkg) {
    if (direct) {
        return directScopeFromPackage(name, pkg) || 'runtime';
    }
    const scopes = new Set();
    for (const root of rootCauses) {
        const scope = directScopeFromPackage(root, pkg);
        if (scope)
            scopes.add(scope);
    }
    if (scopes.has('runtime'))
        return 'runtime';
    if (scopes.has('dev'))
        return 'dev';
    if (scopes.has('optional'))
        return 'optional';
    if (scopes.has('peer'))
        return 'peer';
    return 'runtime';
}
function buildOrigins(rootCauses, workspaceList, workspaceEnabled, maxTop) {
    const origins = {
        rootPackageCount: rootCauses.length,
        topRootPackages: rootCauses.slice(0, maxTop)
    };
    if (workspaceEnabled && workspaceList && workspaceList.length > 0) {
        origins.workspaces = workspaceList;
    }
    return origins;
}
function determineBuildRisk(hasNative, hasInstallScripts) {
    if (hasNative && hasInstallScripts)
        return 'red';
    if (hasNative || hasInstallScripts)
        return 'amber';
    return 'green';
}
async function gatherPackageInsights(name, projectPath, metaCache, statCache) {
    var _a;
    const meta = await loadPackageMeta(name, projectPath, metaCache);
    if (!meta) {
        return {
            deprecated: false,
            nodeEngine: null,
            dependencySurface: { deps: 0, dev: 0, peer: 0, opt: 0 },
            build: { native: false, installScripts: false },
            tsTypes: 'unknown'
        };
    }
    const pkg = (meta === null || meta === void 0 ? void 0 : meta.pkg) || {};
    const dir = meta === null || meta === void 0 ? void 0 : meta.dir;
    const stats = dir ? await calculatePackageStats(dir, statCache) : undefined;
    const dependencySurface = {
        deps: Object.keys(pkg.dependencies || {}).length,
        dev: Object.keys(pkg.devDependencies || {}).length,
        peer: Object.keys(pkg.peerDependencies || {}).length,
        opt: Object.keys(pkg.optionalDependencies || {}).length
    };
    const scripts = pkg.scripts || {};
    const deprecated = Boolean(pkg.deprecated);
    const nodeEngine = typeof ((_a = pkg.engines) === null || _a === void 0 ? void 0 : _a.node) === 'string' ? pkg.engines.node : null;
    const hasDefinitelyTyped = await hasDefinitelyTypedPackage(name, projectPath, metaCache);
    const tsTypes = determineTypes(pkg, (stats === null || stats === void 0 ? void 0 : stats.hasDts) || false, hasDefinitelyTyped);
    const build = {
        native: Boolean((stats === null || stats === void 0 ? void 0 : stats.hasNativeBinary) || (stats === null || stats === void 0 ? void 0 : stats.hasBindingGyp) || scriptsContainNativeBuild(scripts)),
        installScripts: hasInstallScripts(scripts)
    };
    return {
        deprecated,
        nodeEngine,
        dependencySurface,
        build,
        tsTypes
    };
}
async function loadPackageMeta(name, projectPath, cache) {
    if (cache.has(name))
        return cache.get(name);
    try {
        const pkgJsonPath = require.resolve(path_1.default.join(name, 'package.json'), { paths: [projectPath] });
        const pkgRaw = await promises_1.default.readFile(pkgJsonPath, 'utf8');
        const pkg = JSON.parse(pkgRaw);
        const meta = { pkg, dir: path_1.default.dirname(pkgJsonPath) };
        cache.set(name, meta);
        return meta;
    }
    catch (err) {
        return undefined;
    }
}
function toDefinitelyTypedPackageName(name) {
    if (name.startsWith('@types/'))
        return name;
    if (name.startsWith('@')) {
        const scoped = name.slice(1).split('/');
        if (scoped.length < 2)
            return undefined;
        return `@types/${scoped[0]}__${scoped[1]}`;
    }
    return `@types/${name}`;
}
async function hasDefinitelyTypedPackage(name, projectPath, cache) {
    if (name.startsWith('@types/'))
        return true;
    const typesName = toDefinitelyTypedPackageName(name);
    if (!typesName)
        return false;
    const meta = await loadPackageMeta(typesName, projectPath, cache);
    return Boolean(meta);
}
async function calculatePackageStats(dir, cache) {
    if (cache.has(dir))
        return cache.get(dir);
    let hasDts = false;
    let hasNativeBinary = false;
    let hasBindingGyp = false;
    async function walk(current) {
        const entries = await promises_1.default.readdir(current, { withFileTypes: true });
        for (const entry of entries) {
            const full = path_1.default.join(current, entry.name);
            if (entry.isSymbolicLink())
                continue;
            if (entry.isDirectory()) {
                await walk(full);
            }
            else if (entry.isFile()) {
                if (entry.name.endsWith('.d.ts'))
                    hasDts = true;
                if (entry.name.endsWith('.node'))
                    hasNativeBinary = true;
                if (entry.name === 'binding.gyp')
                    hasBindingGyp = true;
            }
        }
    }
    try {
        await walk(dir);
    }
    catch (err) {
        // best-effort; ignore inaccessible paths
    }
    const result = { hasDts, hasNativeBinary, hasBindingGyp };
    cache.set(dir, result);
    return result;
}
function determineTypes(pkg, hasDts, hasDefinitelyTyped) {
    const hasBundled = Boolean(pkg.types || pkg.typings || hasDts);
    if (hasBundled)
        return 'bundled';
    if (hasDefinitelyTyped)
        return 'definitelyTyped';
    return 'none';
}
function scriptsContainNativeBuild(scripts) {
    return Object.values(scripts || {}).some((cmd) => typeof cmd === 'string' && /node-?gyp|node-pre-gyp/.test(cmd));
}
function hasInstallScripts(scripts) {
    return ['preinstall', 'install', 'postinstall'].some((key) => typeof (scripts === null || scripts === void 0 ? void 0 : scripts[key]) === 'string' && scripts[key].trim().length > 0);
}
