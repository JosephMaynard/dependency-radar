"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.aggregateData = aggregateData;
const utils_1 = require("./utils");
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
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
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
    const pkg = await (0, utils_1.readPackageJson)(input.projectPath);
    const raw = {
        audit: (_a = input.auditResult) === null || _a === void 0 ? void 0 : _a.data,
        npmLs: (_b = input.npmLsResult) === null || _b === void 0 ? void 0 : _b.data,
        licenseChecker: (_c = input.licenseResult) === null || _c === void 0 ? void 0 : _c.data,
        depcheck: (_d = input.depcheckResult) === null || _d === void 0 ? void 0 : _d.data,
        madge: (_e = input.madgeResult) === null || _e === void 0 ? void 0 : _e.data
    };
    const toolErrors = {};
    if (input.auditResult && !input.auditResult.ok)
        toolErrors['npm-audit'] = input.auditResult.error || 'unknown error';
    if (input.npmLsResult && !input.npmLsResult.ok)
        toolErrors['npm-ls'] = input.npmLsResult.error || 'unknown error';
    if (input.licenseResult && !input.licenseResult.ok)
        toolErrors['license-checker'] = input.licenseResult.error || 'unknown error';
    if (input.depcheckResult && !input.depcheckResult.ok)
        toolErrors['depcheck'] = input.depcheckResult.error || 'unknown error';
    if (input.madgeResult && !input.madgeResult.ok)
        toolErrors['madge'] = input.madgeResult.error || 'unknown error';
    // Get git branch
    const gitBranch = await getGitBranch(input.projectPath);
    const nodeMap = buildNodeMap((_f = input.npmLsResult) === null || _f === void 0 ? void 0 : _f.data, pkg);
    const vulnMap = parseVulnerabilities((_g = input.auditResult) === null || _g === void 0 ? void 0 : _g.data);
    const licenseData = normalizeLicenseData((_h = input.licenseResult) === null || _h === void 0 ? void 0 : _h.data);
    const depcheckUsage = buildUsageInfo((_j = input.depcheckResult) === null || _j === void 0 ? void 0 : _j.data);
    const importInfo = buildImportInfo((_k = input.madgeResult) === null || _k === void 0 ? void 0 : _k.data);
    const maintenanceCache = new Map();
    const packageMetaCache = new Map();
    const packageStatCache = new Map();
    const dependencies = [];
    const licenseFallbackCache = new Map();
    const nodes = Array.from(nodeMap.values());
    const totalDeps = nodes.length;
    let maintenanceIndex = 0;
    for (const node of nodes) {
        const direct = isDirectDependency(node.name, pkg);
        const license = licenseData.byKey.get(node.key) ||
            licenseData.byName.get(node.name) ||
            licenseFallbackCache.get(node.name) ||
            (await (0, utils_1.readLicenseFromPackageJson)(node.name, input.projectPath)) ||
            { license: undefined };
        if (!licenseFallbackCache.has(node.name) && license.license) {
            licenseFallbackCache.set(node.name, license);
        }
        const vulnerabilities = vulnMap.get(node.name) || emptyVulnSummary();
        const licenseRisk = (0, utils_1.licenseRiskLevel)(license.license);
        const vulnRisk = (0, utils_1.vulnRiskLevel)(vulnerabilities.counts);
        const usage = depcheckUsage.get(node.name) ||
            (((_l = input.depcheckResult) === null || _l === void 0 ? void 0 : _l.data)
                ? { status: 'used', reason: 'Not flagged as unused by depcheck' }
                : { status: 'unknown', reason: 'depcheck unavailable' });
        const maintenance = await resolveMaintenance(node.name, maintenanceCache, input.maintenanceEnabled, ++maintenanceIndex, totalDeps, input.onMaintenanceProgress);
        if (!maintenanceCache.has(node.name)) {
            maintenanceCache.set(node.name, maintenance);
        }
        const maintenanceRiskLevel = (0, utils_1.maintenanceRisk)(maintenance.lastPublished);
        const runtimeData = classifyRuntime(node, pkg, nodeMap);
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
            raw: {}
        });
    }
    dependencies.sort((a, b) => a.name.localeCompare(b.name));
    return {
        generatedAt: new Date().toISOString(),
        projectPath: input.projectPath,
        gitBranch,
        maintenanceEnabled: input.maintenanceEnabled,
        dependencies,
        toolErrors,
        raw
    };
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
function normalizeLicenseData(data) {
    const byKey = new Map();
    const byName = new Map();
    if (!data)
        return { byKey, byName };
    Object.entries(data).forEach(([key, value]) => {
        const lic = Array.isArray(value.licenses) ? value.licenses.join(' OR ') : value.licenses;
        const entry = {
            license: lic,
            licenseFile: value.licenseFile || value.licenseFilePath
        };
        byKey.set(key, entry);
        const namePart = key.includes('@', 1) ? key.slice(0, key.lastIndexOf('@')) : key;
        if (!byName.has(namePart))
            byName.set(namePart, entry);
    });
    return { byKey, byName };
}
function buildUsageInfo(depcheckData) {
    const map = new Map();
    if (!depcheckData)
        return map;
    const unused = new Set([...(depcheckData.dependencies || []), ...(depcheckData.devDependencies || [])]);
    unused.forEach((name) => {
        map.set(name, { status: 'unused', reason: 'Marked unused by depcheck' });
    });
    if (Array.isArray(depcheckData.dependencies) || Array.isArray(depcheckData.devDependencies)) {
        Object.keys(depcheckData.missing || {}).forEach((name) => {
            if (!map.has(name)) {
                map.set(name, { status: 'unknown', reason: 'Missing according to depcheck' });
            }
        });
    }
    return map;
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
function classifyRuntime(node, pkg, map) {
    if (pkg.dependencies && pkg.dependencies[node.name]) {
        return { classification: 'runtime', reason: 'Declared in dependencies' };
    }
    if (pkg.devDependencies && pkg.devDependencies[node.name]) {
        return { classification: 'dev-only', reason: 'Declared in devDependencies' };
    }
    if (node.dev) {
        return { classification: 'dev-only', reason: 'npm ls marks as dev dependency' };
    }
    const hasRuntimeParent = Array.from(node.parents).some((parentKey) => {
        const parent = map.get(parentKey);
        return parent ? !parent.dev : false;
    });
    if (hasRuntimeParent) {
        return { classification: 'runtime', reason: 'Transitive of runtime dependency' };
    }
    return { classification: 'build-time', reason: 'Only seen in dev dependency tree' };
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
