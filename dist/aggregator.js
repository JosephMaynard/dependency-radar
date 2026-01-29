"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.aggregateData = aggregateData;
const utils_1 = require("./utils");
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
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
function formatProjectDir(projectPath) {
    const home = os_1.default.homedir();
    const relative = path_1.default.relative(home, projectPath);
    if (relative && !relative.startsWith('..') && !path_1.default.isAbsolute(relative)) {
        return `/${relative.split(path_1.default.sep).join('/')}`;
    }
    return projectPath;
}
async function aggregateData(input) {
    var _a, _b, _c, _d, _e, _f, _g, _h;
    const pkg = input.pkgOverride || (await (0, utils_1.readPackageJson)(input.projectPath));
    // Get git branch
    const gitBranch = await getGitBranch(input.projectPath);
    const nodeMap = buildNodeMap((_a = input.npmLsResult) === null || _a === void 0 ? void 0 : _a.data, pkg);
    const vulnMap = parseVulnerabilities((_b = input.auditResult) === null || _b === void 0 ? void 0 : _b.data);
    const importGraph = normalizeImportGraph((_c = input.importGraphResult) === null || _c === void 0 ? void 0 : _c.data);
    const usageResult = buildUsageSummary(importGraph, input.projectPath);
    const outdatedById = buildOutdatedMap(input.outdatedResult);
    const outdatedUnknownNames = new Set(((_d = input.outdatedResult) === null || _d === void 0 ? void 0 : _d.unknownNames) || []);
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
        const importUsage = usageResult.summary.get(node.name);
        const runtimeImpact = usageResult.runtimeImpact.get(node.name);
        const introduction = determineIntroduction(direct, rootCauses, runtimeImpact);
        const origins = buildOrigins(rootCauses, (_e = input.workspaceUsage) === null || _e === void 0 ? void 0 : _e.get(node.name), input.workspaceEnabled, MAX_TOP_ROOT_PACKAGES);
        const execution = packageInsights.execution;
        const id = node.key;
        const upgrade = buildUpgradeBlock(packageInsights);
        const outdated = resolveOutdated(node, direct, outdatedById, outdatedUnknownNames);
        // Group fields by reviewer question to keep the JSON readable and source-agnostic.
        // Optional fields are only attached when meaningful to keep the payload sparse.
        const upgradeRecord = {
            nodeEngine: packageInsights.nodeEngine,
            ...(outdated ? { outdatedStatus: outdated.status } : {}),
            ...((outdated === null || outdated === void 0 ? void 0 : outdated.latestVersion) ? { latestVersion: outdated.latestVersion } : {}),
            ...((upgrade === null || upgrade === void 0 ? void 0 : upgrade.blockers) ? { blockers: upgrade.blockers } : {}),
            ...((upgrade === null || upgrade === void 0 ? void 0 : upgrade.blocksNodeMajor) ? { blocksNodeMajor: upgrade.blocksNodeMajor } : {})
        };
        dependencies[id] = {
            package: {
                id,
                name: node.name,
                version: node.version,
                deprecated: packageInsights.deprecated,
                links: {
                    npm: `https://www.npmjs.com/package/${node.name}`,
                    ...(((_f = packageInsights.links) === null || _f === void 0 ? void 0 : _f.repository) ? { repository: packageInsights.links.repository } : {}),
                    ...(((_g = packageInsights.links) === null || _g === void 0 ? void 0 : _g.homepage) ? { homepage: packageInsights.links.homepage } : {}),
                    ...(((_h = packageInsights.links) === null || _h === void 0 ? void 0 : _h.bugs) ? { bugs: packageInsights.links.bugs } : {})
                }
            },
            compliance: {
                license: licenseValue,
                licenseRisk
            },
            security: {
                vulnerabilities: {
                    critical: vulnerabilities.counts.critical,
                    high: vulnerabilities.counts.high,
                    moderate: vulnerabilities.counts.moderate,
                    low: vulnerabilities.counts.low,
                    highest: vulnerabilities.highestSeverity
                },
                vulnRisk
            },
            upgrade: upgradeRecord,
            usage: {
                direct,
                scope,
                depth: node.depth,
                origins,
                ...(introduction ? { introduction } : {}),
                ...(runtimeImpact ? { runtimeImpact } : {}),
                ...(importUsage ? { importUsage } : {}),
                tsTypes: packageInsights.tsTypes
            },
            graph: {
                fanIn: node.parents.size,
                fanOut: node.children.size,
                dependencySurface: packageInsights.dependencySurface
            },
            ...(execution ? { execution } : {})
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
            projectDir: formatProjectDir(input.projectPath)
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
function buildOutdatedMap(outdatedResult) {
    const map = new Map();
    if (!outdatedResult || !Array.isArray(outdatedResult.entries))
        return map;
    for (const entry of outdatedResult.entries) {
        if (!entry || typeof entry.name !== 'string' || typeof entry.currentVersion !== 'string')
            continue;
        const key = `${entry.name}@${entry.currentVersion}`;
        if (entry.status === 'patch' || entry.status === 'minor' || entry.status === 'major') {
            if (entry.latestVersion) {
                map.set(key, { status: entry.status, latestVersion: entry.latestVersion });
            }
            else {
                map.set(key, { status: 'unknown' });
            }
            continue;
        }
        map.set(key, { status: 'unknown' });
    }
    return map;
}
function resolveOutdated(node, direct, outdatedById, unknownNames) {
    const entry = outdatedById.get(node.key);
    if (entry) {
        if (entry.status === 'patch' || entry.status === 'minor' || entry.status === 'major') {
            if (entry.latestVersion) {
                return { status: entry.status, latestVersion: entry.latestVersion };
            }
            return { status: 'unknown' };
        }
        return { status: 'unknown' };
    }
    if (direct && unknownNames.has(node.name)) {
        return { status: 'unknown' };
    }
    return undefined;
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
function normalizeImportGraph(data) {
    if (data && typeof data === 'object' && data.packages) {
        return {
            packages: data.packages || {},
            packageCounts: data.packageCounts || {}
        };
    }
    return { packages: {} };
}
function normalizeImportPath(file, projectPath) {
    if (!file || typeof file !== 'string')
        return undefined;
    if (file.includes('node_modules'))
        return undefined;
    let relativePath = file;
    if (path_1.default.isAbsolute(file)) {
        relativePath = path_1.default.relative(projectPath, file);
    }
    if (!relativePath)
        return undefined;
    const trimmed = relativePath.replace(/^[.][\\/]/, '');
    const normalized = trimmed.replace(/\\/g, '/');
    if (!normalized || normalized.startsWith('..'))
        return undefined;
    if (normalized.includes('node_modules'))
        return undefined;
    return normalized;
}
function buildUsageSummary(graph, projectPath) {
    var _a;
    const summary = new Map();
    const runtimeImpact = new Map();
    const byDep = new Map();
    const packages = graph.packages || {};
    for (const [file, deps] of Object.entries(packages)) {
        if (!Array.isArray(deps) || deps.length === 0)
            continue;
        const normalizedFile = normalizeImportPath(file, projectPath);
        if (!normalizedFile)
            continue;
        const counts = ((_a = graph.packageCounts) === null || _a === void 0 ? void 0 : _a[file]) || {};
        const uniqueDeps = new Set(deps.filter((dep) => typeof dep === 'string' && dep));
        for (const dep of uniqueDeps) {
            if (!byDep.has(dep))
                byDep.set(dep, new Map());
            const fileMap = byDep.get(dep);
            const count = typeof counts[dep] === 'number' ? counts[dep] : 1;
            fileMap.set(normalizedFile, count);
        }
    }
    for (const [dep, fileMap] of byDep.entries()) {
        const entries = Array.from(fileMap.entries()).map(([file, count]) => ({
            file,
            count,
            depth: file.split('/').length,
            isTest: isTestFile(file)
        }));
        // Rank: prefer non-test files, then higher import counts, then closer to root.
        entries.sort((a, b) => {
            if (a.isTest !== b.isTest)
                return a.isTest ? 1 : -1;
            if (b.count !== a.count)
                return b.count - a.count;
            if (a.depth !== b.depth)
                return a.depth - b.depth;
            return a.file.localeCompare(b.file);
        });
        summary.set(dep, {
            fileCount: fileMap.size,
            topFiles: entries.slice(0, 5).map((entry) => entry.file)
        });
        runtimeImpact.set(dep, determineRuntimeImpactFromFiles(Array.from(fileMap.keys())));
    }
    return { summary, runtimeImpact };
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
function isTestFile(file) {
    return /(^|\/)(__tests__|__mocks__|test|tests)(\/|$)/.test(file) || /\.(test|spec)\./.test(file);
}
function isToolingFile(file) {
    return /(^|\/)(eslint|prettier|stylelint|commitlint|lint-staged|husky)[^\/]*\./.test(file);
}
function isBuildFile(file) {
    return /(^|\/)(webpack|rollup|vite|tsconfig|babel|swc|esbuild|parcel|gulpfile|gruntfile|postcss|tailwind)[^\/]*\./.test(file);
}
function determineRuntimeImpactFromFiles(files) {
    const categories = new Set();
    for (const file of files) {
        if (isTestFile(file)) {
            categories.add('testing');
        }
        else if (isToolingFile(file)) {
            categories.add('tooling');
        }
        else if (isBuildFile(file)) {
            categories.add('build');
        }
        else {
            categories.add('runtime');
        }
    }
    if (categories.size === 0)
        return 'runtime';
    if (categories.size > 1)
        return 'mixed';
    return Array.from(categories)[0];
}
const TOOLING_PACKAGES = new Set([
    'eslint',
    'prettier',
    'ts-node',
    'typescript',
    'babel',
    '@babel/core',
    'rollup',
    'webpack',
    'vite',
    'parcel',
    'swc',
    '@swc/core',
    'ts-jest',
    'eslint-config-prettier',
    'eslint-plugin-import',
    'lint-staged',
    'husky'
]);
const FRAMEWORK_PACKAGES = new Set([
    'next',
    'react-scripts',
    '@angular/core',
    '@angular/cli',
    'vue',
    'nuxt',
    'svelte',
    '@sveltejs/kit',
    'gatsby',
    'ember-cli',
    'remix',
    'expo'
]);
function isToolingPackage(name) {
    if (TOOLING_PACKAGES.has(name))
        return true;
    if (name.startsWith('@typescript-eslint/'))
        return true;
    if (name.startsWith('eslint-'))
        return true;
    return false;
}
function isFrameworkPackage(name) {
    return FRAMEWORK_PACKAGES.has(name);
}
// Heuristic-only classification for why a dependency exists. Kept deterministic and bounded.
function determineIntroduction(direct, rootCauses, runtimeImpact) {
    if (direct)
        return 'direct';
    if (runtimeImpact === 'testing')
        return 'testing';
    if (rootCauses.length > 0 && rootCauses.every((root) => isToolingPackage(root)))
        return 'tooling';
    if (rootCauses.some((root) => isFrameworkPackage(root)))
        return 'framework';
    if (rootCauses.length > 0)
        return 'transitive';
    return 'unknown';
}
// Upgrade blockers derived only from local metadata (no external lookups).
function buildUpgradeBlock(insights) {
    var _a;
    const blockers = [];
    if (insights.nodeEngine)
        blockers.push('nodeEngine');
    if (insights.dependencySurface.peer > 0)
        blockers.push('peerDependency');
    if ((_a = insights.execution) === null || _a === void 0 ? void 0 : _a.native)
        blockers.push('nativeBindings');
    if (insights.deprecated)
        blockers.push('deprecated');
    if (blockers.length === 0)
        return undefined;
    return {
        blocksNodeMajor: true,
        blockers
    };
}
async function gatherPackageInsights(name, projectPath, metaCache, statCache) {
    var _a;
    const meta = await loadPackageMeta(name, projectPath, metaCache);
    if (!meta) {
        return {
            deprecated: false,
            nodeEngine: null,
            dependencySurface: { deps: 0, dev: 0, peer: 0, opt: 0 },
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
    const links = extractPackageLinks(pkg);
    const execution = await deriveExecutionInfo(scripts, dir, stats);
    return {
        deprecated,
        nodeEngine,
        dependencySurface,
        links,
        execution,
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
const REPO_SHORTHAND_HOSTS = {
    github: 'github.com',
    gitlab: 'gitlab.com',
    bitbucket: 'bitbucket.org'
};
function normalizeUrl(raw) {
    const trimmed = raw.trim();
    if (!trimmed)
        return undefined;
    let url = trimmed.replace(/^git\+/, '');
    if (url.startsWith('ssh://')) {
        url = url.slice('ssh://'.length);
        if (url.startsWith('git@')) {
            const match = url.match(/^git@([^:]+):(.+)$/);
            if (match) {
                url = `https://${match[1]}/${match[2]}`;
            }
            else {
                url = `https://${url}`;
            }
        }
        else {
            url = `https://${url}`;
        }
    }
    if (url.startsWith('git@')) {
        const match = url.match(/^git@([^:]+):(.+)$/);
        if (match) {
            url = `https://${match[1]}/${match[2]}`;
        }
    }
    const shorthand = url.match(/^(github|gitlab|bitbucket):(.+)$/i);
    if (shorthand) {
        const host = REPO_SHORTHAND_HOSTS[shorthand[1].toLowerCase()];
        url = `https://${host}/${shorthand[2]}`;
    }
    if (url.startsWith('git://')) {
        url = `https://${url.slice('git://'.length)}`;
    }
    const hashIndex = url.indexOf('#');
    const hash = hashIndex === -1 ? '' : url.slice(hashIndex);
    const base = hashIndex === -1 ? url : url.slice(0, hashIndex);
    const cleaned = base.endsWith('.git') ? base.slice(0, -4) : base;
    return cleaned + hash;
}
function normalizeLinkValue(value) {
    if (!value)
        return undefined;
    if (typeof value === 'string')
        return normalizeUrl(value);
    if (typeof value === 'object' && typeof value.url === 'string') {
        return normalizeUrl(value.url);
    }
    return undefined;
}
function extractPackageLinks(pkg) {
    const repository = normalizeLinkValue(pkg === null || pkg === void 0 ? void 0 : pkg.repository);
    const homepage = normalizeLinkValue(pkg === null || pkg === void 0 ? void 0 : pkg.homepage);
    const bugs = normalizeLinkValue(pkg === null || pkg === void 0 ? void 0 : pkg.bugs);
    if (!repository && !homepage && !bugs)
        return undefined;
    return {
        ...(repository ? { repository } : {}),
        ...(homepage ? { homepage } : {}),
        ...(bugs ? { bugs } : {})
    };
}
const LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare'];
const EXECUTION_SIGNAL_ORDER = [
    'network-access',
    'dynamic-exec',
    'child-process',
    'encoding',
    'obfuscated',
    'reads-env',
    'reads-home',
    'uses-ssh'
];
const INSTALL_SCRIPT_MAX_BYTES = 200000;
const COMPLEXITY_THRESHOLD = 12;
function collectLifecycleScripts(scripts) {
    const lifecycle = {};
    for (const hook of LIFECYCLE_HOOKS) {
        const cmd = scripts === null || scripts === void 0 ? void 0 : scripts[hook];
        if (typeof cmd === 'string' && cmd.trim().length > 0) {
            lifecycle[hook] = cmd.trim();
        }
    }
    return lifecycle;
}
function scriptsContainNativeTooling(scripts) {
    return Object.values(scripts || {}).some((cmd) => typeof cmd === 'string' && /node-?gyp|node-pre-gyp|prebuild/i.test(cmd));
}
function scoreLifecycleScripts(lifecycleScripts) {
    const commands = Object.values(lifecycleScripts).filter((cmd) => typeof cmd === 'string');
    const combined = commands.join(' ');
    if (!combined)
        return 0;
    const lengthScore = Math.ceil(combined.length / 40);
    const andCount = (combined.match(/&&/g) || []).length;
    const orCount = (combined.match(/\|\|/g) || []).length;
    const semicolons = (combined.match(/;/g) || []).length;
    const pipeCount = Math.max(0, (combined.match(/\|/g) || []).length - orCount * 2);
    const inlineNodeExec = (combined.match(/\bnode\s+-[ep]\b/gi) || []).length;
    const inlineEval = (combined.match(/\beval\s*\(/g) || []).length;
    const inlineFunction = (combined.match(/new\s+Function\s*\(/g) || []).length;
    return lengthScore + (andCount + orCount + semicolons + pipeCount) * 2 + (inlineNodeExec + inlineEval + inlineFunction) * 5;
}
function tokenizeCommand(command) {
    var _a, _b;
    const tokens = [];
    const matcher = /"([^"]*)"|'([^']*)'|(\S+)/g;
    let match;
    while ((match = matcher.exec(command))) {
        tokens.push((_b = (_a = match[1]) !== null && _a !== void 0 ? _a : match[2]) !== null && _b !== void 0 ? _b : match[3]);
    }
    return tokens;
}
function isNodeToken(token) {
    const base = path_1.default.basename(token).toLowerCase();
    return base === 'node' || base === 'node.exe';
}
function extractNodeScriptPath(command) {
    const tokens = tokenizeCommand(command);
    for (let i = 0; i < tokens.length; i += 1) {
        if (!isNodeToken(tokens[i]))
            continue;
        let idx = i + 1;
        while (idx < tokens.length) {
            const token = tokens[idx];
            if (token === '-e' || token === '-p' || token === '--eval') {
                return undefined;
            }
            if (token === '-r' || token === '--require') {
                idx += 2;
                continue;
            }
            if (token.startsWith('-')) {
                idx += 1;
                continue;
            }
            const cleaned = token.replace(/[;|&]+$/, '');
            if (cleaned.includes('://'))
                return undefined;
            if (cleaned.endsWith('.js') || cleaned.endsWith('.cjs') || cleaned.endsWith('.mjs')) {
                return cleaned;
            }
            return undefined;
        }
    }
    return undefined;
}
function findReferencedInstallScript(lifecycleScripts) {
    for (const hook of LIFECYCLE_HOOKS) {
        const command = lifecycleScripts[hook];
        if (!command)
            continue;
        const candidate = extractNodeScriptPath(command);
        if (candidate)
            return candidate;
    }
    return undefined;
}
async function readInstallScriptFile(scriptPath, packageDir) {
    const resolvedDir = path_1.default.resolve(packageDir);
    const resolvedPath = path_1.default.resolve(resolvedDir, scriptPath);
    if (!resolvedPath.startsWith(resolvedDir + path_1.default.sep))
        return undefined;
    try {
        const stat = await promises_1.default.stat(resolvedPath);
        if (!stat.isFile())
            return undefined;
        if (stat.size > INSTALL_SCRIPT_MAX_BYTES)
            return undefined;
        return await promises_1.default.readFile(resolvedPath, 'utf8');
    }
    catch {
        return undefined;
    }
}
function textHasAny(text, patterns) {
    return patterns.some((pattern) => pattern.test(text));
}
function detectScriptSignals(text, signals) {
    // Signals are derived from static text inspection only: no code execution and no import walking.
    // They are NOT malware detection; they merely highlight review-worthy install-time behavior.
    // "network-access" surfaces install scripts that fetch remote resources (review for expected downloads; does NOT imply exfiltration).
    if (textHasAny(text, [/\bcurl\b/i, /\bwget\b/i, /https?:\/\//i, /\bfetch\s*\(/i, /\baxios\b/i, /node-fetch/i])) {
        signals.add('network-access');
    }
    // "reads-env" highlights environment access (does NOT imply exfiltration).
    if (textHasAny(text, [/\bprocess\.env\b/, /\bprintenv\b/i, /\benv\s*\|/i])) {
        signals.add('reads-env');
    }
    // "reads-home" highlights access to user home paths (does NOT imply credential theft).
    if (textHasAny(text, [/\$HOME\b/, /process\.env\.HOME\b/, /os\.homedir\s*\(/, /~\//])) {
        signals.add('reads-home');
    }
    // "uses-ssh" flags access to SSH-related paths (does NOT imply key exfiltration).
    if (textHasAny(text, [/\.ssh\b/i, /id_rsa\b/i, /known_hosts\b/i, /\.npmrc\b/i])) {
        signals.add('uses-ssh');
    }
}
function isObfuscated(text) {
    const lines = text.split(/\r?\n/);
    let longest = 0;
    for (const line of lines) {
        if (line.length > longest)
            longest = line.length;
        if (longest >= 4000)
            return true;
    }
    if (text.length >= 2000) {
        const nonWhitespace = text.replace(/\s/g, '');
        const ratio = nonWhitespace.length / text.length;
        if (ratio > 0.9)
            return true;
    }
    return /[A-Za-z0-9+/]{800,}={0,2}/.test(text);
}
function detectFileSignals(text, signals) {
    // Signals from a single directly-referenced JS file (no execution, no imports, no deep scanning).
    // These are review cues only and do NOT imply malicious intent.
    detectScriptSignals(text, signals);
    // "dynamic-exec" flags dynamic code execution APIs (does NOT imply malicious behavior).
    if (textHasAny(text, [/\beval\s*\(/, /new\s+Function\s*\(/, /\bvm\.runIn/i])) {
        signals.add('dynamic-exec');
    }
    // "child-process" flags process spawning (does NOT imply abuse).
    if (textHasAny(text, [/\bchild_process\.exec\b/, /\bspawn\s*\(/, /\bexecSync\s*\(/])) {
        signals.add('child-process');
    }
    // "encoding" flags explicit encode/decode flows (does NOT imply obfuscation intent).
    if (textHasAny(text, [/Buffer\.from\s*\(/, /\.toString\(\s*['"]base64['"]\s*\)/i, /\batob\s*\(/, /\bbtoa\s*\(/])) {
        signals.add('encoding');
    }
    // "obfuscated" flags minified or opaque install-time code (does NOT imply malware).
    if (isObfuscated(text)) {
        signals.add('obfuscated');
    }
}
function determineExecutionRisk(hasScripts, hasSignals, highComplexity, hooks) {
    const hasInstallHook = hooks.includes('install') || hooks.includes('postinstall');
    if (hasScripts && (hasSignals || (highComplexity && hasInstallHook)))
        return 'red';
    return 'amber';
}
async function deriveExecutionInfo(scripts, packageDir, stats) {
    const lifecycleScripts = collectLifecycleScripts(scripts);
    const hooks = LIFECYCLE_HOOKS.filter((hook) => Boolean(lifecycleScripts[hook]));
    const hasScripts = hooks.length > 0;
    const hasNative = Boolean((stats === null || stats === void 0 ? void 0 : stats.hasNativeBinary) || (stats === null || stats === void 0 ? void 0 : stats.hasBindingGyp) || scriptsContainNativeTooling(scripts));
    if (!hasScripts && !hasNative)
        return undefined;
    const signals = new Set();
    const combinedScripts = hooks.map((hook) => lifecycleScripts[hook]).join('\n');
    if (combinedScripts) {
        detectScriptSignals(combinedScripts, signals);
    }
    if (hasScripts && packageDir) {
        const referencedScript = findReferencedInstallScript(lifecycleScripts);
        if (referencedScript) {
            const fileContent = await readInstallScriptFile(referencedScript, packageDir);
            if (fileContent) {
                detectFileSignals(fileContent, signals);
            }
        }
    }
    const complexityScore = hasScripts ? scoreLifecycleScripts(lifecycleScripts) : 0;
    const complexity = complexityScore >= COMPLEXITY_THRESHOLD ? complexityScore : undefined;
    const signalList = EXECUTION_SIGNAL_ORDER.filter((signal) => signals.has(signal));
    const scriptsInfo = {
        hooks,
        ...(complexity !== undefined ? { complexity } : {}),
        ...(signalList.length > 0 ? { signals: signalList } : {})
    };
    const risk = determineExecutionRisk(hasScripts, signalList.length > 0, complexity !== undefined, hooks);
    const execution = { risk };
    // Native is surface description only; not a behavioral signal.
    if (hasNative)
        execution.native = true;
    if (hasScripts)
        execution.scripts = scriptsInfo;
    return execution;
}
