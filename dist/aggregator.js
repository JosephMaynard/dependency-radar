"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.aggregateData = aggregateData;
const utils_1 = require("./utils");
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
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
/**
 * Normalize repository URLs to browsable HTTPS format.
 * Handles: git+https://, git://, github:user/repo, git@github.com:user/repo.git
 */
function normalizeRepoUrl(url) {
    if (!url)
        return url;
    // Handle shorthand: github:user/repo or user/repo
    if (url.match(/^(github:|gitlab:|bitbucket:)?[\w-]+\/[\w.-]+$/)) {
        const cleaned = url.replace(/^(github:|gitlab:|bitbucket:)/, '');
        const host = url.startsWith('gitlab:') ? 'gitlab.com'
            : url.startsWith('bitbucket:') ? 'bitbucket.org'
                : 'github.com';
        return `https://${host}/${cleaned}`;
    }
    // Handle git+https:// or git:// prefix
    let normalized = url.replace(/^git\+/, '').replace(/^git:\/\//, 'https://');
    // Handle git@host:user/repo.git SSH format
    normalized = normalized.replace(/^git@([^:]+):(.+)$/, 'https://$1/$2');
    // Remove .git suffix
    normalized = normalized.replace(/\.git$/, '');
    return normalized;
}
async function aggregateData(input) {
    var _a, _b, _c, _d, _e, _f, _g;
    const pkg = input.pkgOverride || (await (0, utils_1.readPackageJson)(input.projectPath));
    const raw = {
        audit: (_a = input.auditResult) === null || _a === void 0 ? void 0 : _a.data,
        npmLs: (_b = input.npmLsResult) === null || _b === void 0 ? void 0 : _b.data,
        importGraph: (_c = input.importGraphResult) === null || _c === void 0 ? void 0 : _c.data
    };
    const toolErrors = {};
    if (input.auditResult && !input.auditResult.ok)
        toolErrors['npm-audit'] = input.auditResult.error || 'unknown error';
    if (input.npmLsResult && !input.npmLsResult.ok)
        toolErrors['npm-ls'] = input.npmLsResult.error || 'unknown error';
    if (input.importGraphResult && !input.importGraphResult.ok)
        toolErrors['import-graph'] = input.importGraphResult.error || 'unknown error';
    // Get git branch
    const gitBranch = await getGitBranch(input.projectPath);
    const nodeMap = buildNodeMap((_d = input.npmLsResult) === null || _d === void 0 ? void 0 : _d.data, pkg);
    const vulnMap = parseVulnerabilities((_e = input.auditResult) === null || _e === void 0 ? void 0 : _e.data);
    const importGraph = normalizeImportGraph((_f = input.importGraphResult) === null || _f === void 0 ? void 0 : _f.data);
    const importInfo = buildImportInfo(importGraph.files);
    const importAnalysis = buildImportAnalysis(importGraph, pkg);
    const packageUsageCounts = new Map(Object.entries(importAnalysis.packageHotness));
    const maintenanceCache = new Map();
    const runtimeCache = new Map();
    const packageMetaCache = new Map();
    const packageStatCache = new Map();
    const dependencies = [];
    const licenseCache = new Map();
    const nodeEngineRanges = [];
    const nodes = Array.from(nodeMap.values());
    const totalDeps = nodes.length;
    let maintenanceIndex = 0;
    for (const node of nodes) {
        const direct = isDirectDependency(node.name, pkg);
        const cachedLicense = licenseCache.get(node.name);
        const license = cachedLicense ||
            (await (0, utils_1.readLicenseFromPackageJson)(node.name, input.projectPath)) ||
            { license: undefined };
        if (!licenseCache.has(node.name) && (license.license || license.licenseFile)) {
            licenseCache.set(node.name, license);
        }
        const vulnerabilities = vulnMap.get(node.name) || emptyVulnSummary();
        const licenseRisk = (0, utils_1.licenseRiskLevel)(license.license);
        const vulnRisk = (0, utils_1.vulnRiskLevel)(vulnerabilities.counts);
        const usage = buildUsageInfo(node.name, packageUsageCounts, pkg);
        const maintenance = await resolveMaintenance(node.name, maintenanceCache, input.maintenanceEnabled, ++maintenanceIndex, totalDeps, input.onMaintenanceProgress);
        if (!maintenanceCache.has(node.name)) {
            maintenanceCache.set(node.name, maintenance);
        }
        const maintenanceRiskLevel = (0, utils_1.maintenanceRisk)(maintenance.lastPublished);
        const runtimeData = classifyRuntime(node.key, pkg, nodeMap, runtimeCache);
        // Calculate root causes (direct dependencies that cause this to be installed)
        const rootCauses = findRootCauses(node, nodeMap, pkg);
        // Build dependedOnBy and dependsOn lists
        const dependedOnBy = Array.from(node.parents).map(key => {
            const parent = nodeMap.get(key);
            return parent ? parent.name : key.split('@')[0];
        });
        const dependsOn = Array.from(node.children).map(key => {
            const child = nodeMap.get(key);
            return child ? child.name : key.split('@')[0];
        });
        const packageInsights = await gatherPackageInsights(node.name, input.projectPath, packageMetaCache, packageStatCache, node.parents.size, node.children.size, dependedOnBy, dependsOn);
        if (packageInsights.identity.nodeEngine) {
            nodeEngineRanges.push(packageInsights.identity.nodeEngine);
        }
        dependencies.push({
            name: node.name,
            version: node.version,
            key: node.key,
            direct,
            transitive: !direct,
            depth: node.depth,
            parents: Array.from(node.parents),
            rootCauses,
            license,
            licenseRisk,
            vulnerabilities,
            vulnRisk,
            maintenance,
            maintenanceRisk: maintenanceRiskLevel,
            usage,
            identity: packageInsights.identity,
            dependencySurface: packageInsights.dependencySurface,
            sizeFootprint: packageInsights.sizeFootprint,
            buildPlatform: packageInsights.buildPlatform,
            moduleSystem: packageInsights.moduleSystem,
            typescript: packageInsights.typescript,
            graph: packageInsights.graph,
            links: packageInsights.links,
            importInfo,
            runtimeClass: runtimeData.classification,
            runtimeReason: runtimeData.reason,
            outdated: { status: 'unknown' },
            raw: {
                workspacePackages: ((_g = input.workspaceUsage) === null || _g === void 0 ? void 0 : _g.get(node.name)) || []
            }
        });
    }
    dependencies.sort((a, b) => a.name.localeCompare(b.name));
    const runtimeVersion = process.version.replace(/^v/, '');
    const runtimeMajor = Number.parseInt(runtimeVersion.split('.')[0], 10);
    const minRequiredMajor = deriveMinRequiredMajor(nodeEngineRanges);
    return {
        generatedAt: new Date().toISOString(),
        projectPath: input.projectPath,
        dependencyRadarVersion,
        gitBranch,
        maintenanceEnabled: input.maintenanceEnabled,
        environment: {
            node: {
                runtimeVersion,
                runtimeMajor: Number.isNaN(runtimeMajor) ? 0 : runtimeMajor,
                minRequiredMajor,
                source: minRequiredMajor === undefined ? 'unknown' : 'dependency-engines'
            }
        },
        dependencies,
        toolErrors,
        raw,
        importAnalysis
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
                entry.items.push({
                    title: vul.title || item.title || vul.name || name,
                    severity: sev,
                    url: vul.url,
                    vulnerableRange: vul.range,
                    fixAvailable: item.fixAvailable,
                    paths: item.nodes
                });
                entry.counts[sev] = (entry.counts[sev] || 0) + 0; // already counted above
            });
            entry.highestSeverity = computeHighestSeverity(entry.counts);
        });
    }
    if (auditData.advisories) {
        Object.values(auditData.advisories).forEach((adv) => {
            const name = adv.module_name || adv.module || 'unknown';
            const severity = normalizeSeverity(adv.severity);
            const entry = ensureEntry(name);
            entry.items.push({
                title: adv.title,
                severity,
                url: adv.url,
                vulnerableRange: adv.vulnerable_versions,
                fixAvailable: adv.fix_available,
                paths: (adv.findings || []).flatMap((f) => f.paths || [])
            });
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
        items: [],
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
    if (data && typeof data === 'object' && data.files && data.packages) {
        return {
            files: data.files || {},
            packages: data.packages || {},
            unresolvedImports: Array.isArray(data.unresolvedImports) ? data.unresolvedImports : []
        };
    }
    return { files: data || {}, packages: {}, unresolvedImports: [] };
}
function buildUsageInfo(name, packageUsageCounts, pkg) {
    const declared = Boolean((pkg.dependencies && pkg.dependencies[name]) || (pkg.devDependencies && pkg.devDependencies[name]));
    const importedCount = packageUsageCounts.get(name) || 0;
    if (importedCount > 0) {
        if (declared) {
            return {
                status: 'imported',
                reason: `Imported by ${importedCount} file${importedCount === 1 ? '' : 's'} (static analysis)`
            };
        }
        return {
            status: 'undeclared',
            reason: 'Imported but not declared (may rely on transitive resolution; pnpm will usually break this)'
        };
    }
    if (declared) {
        return {
            status: 'not-imported',
            reason: 'Declared but never statically imported (may be used via tooling, scripts, or runtime plugins)'
        };
    }
    return {
        status: 'unknown',
        reason: 'Not statically imported; package is likely transitive or used dynamically'
    };
}
function buildImportAnalysis(graph, pkg) {
    const packageImporters = new Map();
    Object.entries(graph.packages || {}).forEach(([file, packages]) => {
        const unique = new Set(packages || []);
        unique.forEach((pkgName) => {
            if (!packageImporters.has(pkgName))
                packageImporters.set(pkgName, new Set());
            packageImporters.get(pkgName).add(file);
        });
    });
    const packageHotness = {};
    packageImporters.forEach((importers, name) => {
        packageHotness[name] = importers.size;
    });
    const declared = new Set([
        ...Object.keys(pkg.dependencies || {}),
        ...Object.keys(pkg.devDependencies || {})
    ]);
    const undeclaredImports = Array.from(packageImporters.keys())
        .filter((name) => !declared.has(name))
        .sort();
    return {
        staticOnly: true,
        notes: [
            'Import analysis is static only.',
            'Dynamic imports, runtime plugin loading, and tooling usage are not evaluated.'
        ],
        packageHotness,
        undeclaredImports,
        unresolvedImports: graph.unresolvedImports || []
    };
}
function buildImportInfo(graphData) {
    if (!graphData || typeof graphData !== 'object')
        return undefined;
    const fanIn = {};
    const fanOut = {};
    Object.entries(graphData).forEach(([file, deps]) => {
        fanOut[file] = Array.isArray(deps) ? deps.length : 0;
        (deps || []).forEach((dep) => {
            fanIn[dep] = (fanIn[dep] || 0) + 1;
        });
    });
    return { files: graphData, fanIn, fanOut };
}
function isDirectDependency(name, pkg) {
    return Boolean((pkg.dependencies && pkg.dependencies[name]) || (pkg.devDependencies && pkg.devDependencies[name]));
}
async function resolveMaintenance(name, cache, maintenanceEnabled, current, total, onProgress) {
    if (cache.has(name))
        return cache.get(name);
    if (!maintenanceEnabled) {
        return { status: 'unknown', reason: 'maintenance checks disabled' };
    }
    onProgress === null || onProgress === void 0 ? void 0 : onProgress(current, total, name);
    try {
        await (0, utils_1.delay)(1000);
        const res = await (0, utils_1.runCommand)('npm', ['view', name, 'time', '--json']);
        const json = JSON.parse(res.stdout || '{}');
        const timestamps = Object.values(json || {}).filter((v) => typeof v === 'string');
        const lastPublished = timestamps.sort().pop();
        if (lastPublished) {
            const risk = (0, utils_1.maintenanceRisk)(lastPublished);
            const status = risk === 'green' ? 'active' : risk === 'amber' ? 'quiet' : risk === 'red' ? 'stale' : 'unknown';
            return { lastPublished, status, reason: 'npm view time' };
        }
        return { status: 'unknown', reason: 'npm view returned no data' };
    }
    catch (err) {
        return { status: 'unknown', reason: 'lookup failed' };
    }
}
function classifyRuntime(nodeKey, pkg, map, cache) {
    const cached = cache.get(nodeKey);
    if (cached)
        return cached;
    const node = map.get(nodeKey);
    if (!node) {
        const fallback = { classification: 'build-time', reason: 'Unknown node in dependency graph' };
        cache.set(nodeKey, fallback);
        return fallback;
    }
    if (pkg.dependencies && pkg.dependencies[node.name]) {
        const result = { classification: 'runtime', reason: 'Declared in dependencies' };
        cache.set(nodeKey, result);
        return result;
    }
    if (pkg.devDependencies && pkg.devDependencies[node.name]) {
        const result = { classification: 'dev-only', reason: 'Declared in devDependencies' };
        cache.set(nodeKey, result);
        return result;
    }
    // Memoized recursion to inherit runtime class from parents; conservative for cycles.
    const parentClasses = [];
    const inProgress = cache.get(`__visiting__${nodeKey}`);
    if (inProgress) {
        const cycleFallback = { classification: 'build-time', reason: 'Dependency cycle; defaulting to build-time' };
        cache.set(nodeKey, cycleFallback);
        return cycleFallback;
    }
    cache.set(`__visiting__${nodeKey}`, { classification: 'build-time', reason: 'visiting' });
    for (const parentKey of node.parents) {
        const parent = map.get(parentKey);
        if (!parent)
            continue;
        const parentClass = classifyRuntime(parentKey, pkg, map, cache).classification;
        parentClasses.push(parentClass);
    }
    cache.delete(`__visiting__${nodeKey}`);
    let result;
    if (parentClasses.includes('runtime')) {
        result = { classification: 'runtime', reason: 'Transitive of runtime dependency' };
    }
    else if (parentClasses.includes('build-time')) {
        result = { classification: 'build-time', reason: 'Transitive of build-time dependency' };
    }
    else {
        result = { classification: 'dev-only', reason: 'Transitive of dev-only dependency' };
    }
    cache.set(nodeKey, result);
    return result;
}
async function gatherPackageInsights(name, projectPath, metaCache, statCache, fanIn, fanOut, dependedOnBy, dependsOn) {
    var _a;
    const meta = await loadPackageMeta(name, projectPath, metaCache);
    const pkg = (meta === null || meta === void 0 ? void 0 : meta.pkg) || {};
    const dir = meta === null || meta === void 0 ? void 0 : meta.dir;
    const stats = dir ? await calculatePackageStats(dir, statCache) : undefined;
    const dependencySurface = {
        dependencies: Object.keys(pkg.dependencies || {}).length,
        devDependencies: Object.keys(pkg.devDependencies || {}).length,
        peerDependencies: Object.keys(pkg.peerDependencies || {}).length,
        optionalDependencies: Object.keys(pkg.optionalDependencies || {}).length,
        hasPeerDependencies: Object.keys(pkg.peerDependencies || {}).length > 0
    };
    const scripts = pkg.scripts || {};
    const identity = {
        deprecated: Boolean(pkg.deprecated),
        nodeEngine: typeof ((_a = pkg.engines) === null || _a === void 0 ? void 0 : _a.node) === 'string' ? pkg.engines.node : null,
        hasRepository: Boolean(pkg.repository),
        hasFunding: Boolean(pkg.funding)
    };
    const moduleSystem = determineModuleSystem(pkg);
    const typescript = determineTypes(pkg, (stats === null || stats === void 0 ? void 0 : stats.hasDts) || false);
    const buildPlatform = {
        nativeBindings: Boolean((stats === null || stats === void 0 ? void 0 : stats.hasNativeBinary) || (stats === null || stats === void 0 ? void 0 : stats.hasBindingGyp) || scriptsContainNativeBuild(scripts)),
        installScripts: hasInstallScripts(scripts)
    };
    const sizeFootprint = {
        installedSize: (stats === null || stats === void 0 ? void 0 : stats.size) || 0,
        fileCount: (stats === null || stats === void 0 ? void 0 : stats.files) || 0
    };
    const graph = {
        fanIn,
        fanOut,
        dependedOnBy,
        dependsOn
    };
    // Extract package links
    const links = {
        npm: `https://www.npmjs.com/package/${name}`
    };
    // Repository can be string or object with url
    if (pkg.repository) {
        if (typeof pkg.repository === 'string') {
            links.repository = normalizeRepoUrl(pkg.repository);
        }
        else if (pkg.repository.url) {
            links.repository = normalizeRepoUrl(pkg.repository.url);
        }
    }
    // Bugs can be string or object with url
    if (pkg.bugs) {
        if (typeof pkg.bugs === 'string') {
            links.bugs = pkg.bugs;
        }
        else if (pkg.bugs.url) {
            links.bugs = pkg.bugs.url;
        }
    }
    // Homepage is a simple string
    if (pkg.homepage && typeof pkg.homepage === 'string') {
        links.homepage = pkg.homepage;
    }
    return {
        identity,
        dependencySurface,
        sizeFootprint,
        buildPlatform,
        moduleSystem,
        typescript,
        graph,
        links
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
async function calculatePackageStats(dir, cache) {
    if (cache.has(dir))
        return cache.get(dir);
    let size = 0;
    let files = 0;
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
                const stat = await promises_1.default.stat(full);
                size += stat.size;
                files += 1;
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
    const result = { size, files, hasDts, hasNativeBinary, hasBindingGyp };
    cache.set(dir, result);
    return result;
}
function determineModuleSystem(pkg) {
    const typeField = pkg.type;
    const hasModuleField = Boolean(pkg.module);
    const hasExports = pkg.exports !== undefined;
    const conditionalExports = typeof pkg.exports === 'object' && pkg.exports !== null;
    let format = 'unknown';
    if (typeField === 'module')
        format = 'esm';
    else if (typeField === 'commonjs')
        format = 'commonjs';
    else if (hasModuleField || hasExports)
        format = 'dual';
    else
        format = 'commonjs';
    return { format, conditionalExports };
}
function determineTypes(pkg, hasDts) {
    const hasBundled = Boolean(pkg.types || pkg.typings || hasDts);
    return { types: hasBundled ? 'bundled' : 'none' };
}
function scriptsContainNativeBuild(scripts) {
    return Object.values(scripts || {}).some((cmd) => typeof cmd === 'string' && /node-?gyp|node-pre-gyp/.test(cmd));
}
function hasInstallScripts(scripts) {
    return ['preinstall', 'install', 'postinstall'].some((key) => typeof (scripts === null || scripts === void 0 ? void 0 : scripts[key]) === 'string' && scripts[key].trim().length > 0);
}
