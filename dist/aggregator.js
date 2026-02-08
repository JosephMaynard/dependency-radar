"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.aggregateData = aggregateData;
const utils_1 = require("./utils");
const license_1 = require("./license");
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
        return [{ name: node.name, version: node.version }];
    }
    // BFS up the parent chain to find all direct dependencies that lead to this
    const rootCauses = new Map();
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
            rootCauses.set(parent.key, { name: parent.name, version: parent.version });
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
    return Array.from(rootCauses.values()).sort((a, b) => {
        const nameCompare = a.name.localeCompare(b.name);
        if (nameCompare !== 0)
            return nameCompare;
        return a.version.localeCompare(b.version);
    });
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
    const nodeMap = buildNodeMap((_a = input.npmLsResult) === null || _a === void 0 ? void 0 : _a.data);
    const vulnMap = parseVulnerabilities((_b = input.auditResult) === null || _b === void 0 ? void 0 : _b.data);
    const importGraph = normalizeImportGraph((_c = input.importGraphResult) === null || _c === void 0 ? void 0 : _c.data);
    const usageResult = buildUsageSummary(importGraph, input.projectPath);
    const outdatedById = buildOutdatedMap(input.outdatedResult);
    const outdatedUnknownNames = new Set(((_d = input.outdatedResult) === null || _d === void 0 ? void 0 : _d.unknownNames) || []);
    const packageMetaCache = new Map();
    const resolvePaths = input.resolvePaths && input.resolvePaths.length > 0
        ? input.resolvePaths
        : [input.projectPath];
    const packageStatCache = new Map();
    const dependencies = {};
    const licenseCache = new Map();
    const nodeEngineRanges = [];
    const nodes = Array.from(nodeMap.values());
    let directCount = 0;
    const MAX_TOP_ROOT_PACKAGES = 10; // cap to keep payload size predictable
    const MAX_TOP_PARENT_PACKAGES = 5; // cap for direct parents to keep payload size predictable
    for (const node of nodes) {
        const direct = isDirectDependency(node.name, pkg);
        if (direct)
            directCount += 1;
        const cacheKey = `${node.name}@${node.version}`;
        const cachedLicense = licenseCache.get(cacheKey);
        const licenseSource = cachedLicense ||
            (node.path
                ? (await (0, utils_1.readLicenseFromPackageDir)(node.path))
                : (await (0, utils_1.readLicenseFromPackageJson)(node.name, resolvePaths, node.version))) ||
            { license: undefined };
        if (!licenseCache.has(cacheKey)) {
            licenseCache.set(cacheKey, licenseSource);
        }
        const vulnerabilities = vulnMap.get(node.name) || emptyVulnSummary();
        const licenseInfo = buildLicenseInfo(licenseSource.license, licenseSource.licenseText);
        const licenseRisk = (0, license_1.pickLicenseRisk)(licenseInfo.licenseIds);
        // Calculate root causes (direct dependencies that cause this to be installed)
        const rootCauses = findRootCauses(node, nodeMap, pkg);
        const packageInsights = await gatherPackageInsights(node.name, node.version, resolvePaths, packageMetaCache, packageStatCache);
        if (packageInsights.nodeEngine) {
            nodeEngineRanges.push(packageInsights.nodeEngine);
        }
        const scope = determineScope(node.name, direct, rootCauses, pkg);
        const importUsage = usageResult.summary.get(node.name);
        const runtimeImpact = usageResult.runtimeImpact.get(node.name);
        const introduction = determineIntroduction(direct, scope, rootCauses, runtimeImpact);
        const parentIds = Array.from(node.parents).sort();
        const origins = buildOrigins(rootCauses, parentIds, (_e = input.workspaceUsage) === null || _e === void 0 ? void 0 : _e.get(node.name), input.workspaceEnabled, MAX_TOP_ROOT_PACKAGES, MAX_TOP_PARENT_PACKAGES);
        const execution = packageInsights.execution;
        const id = node.key;
        const upgrade = buildUpgradeBlock(packageInsights);
        const outdated = resolveOutdated(node, direct, outdatedById, outdatedUnknownNames);
        const subDeps = buildSubDeps(packageInsights.declaredDependencies, node);
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
                ...(packageInsights.description ? { description: packageInsights.description } : {}),
                ...(typeof packageInsights.fileCount === 'number' ? { fileCount: packageInsights.fileCount } : {}),
                ...(packageInsights.hasBin ? { hasBin: true } : {}),
                deprecated: packageInsights.deprecated,
                links: {
                    npm: `https://www.npmjs.com/package/${node.name}`,
                    ...(((_f = packageInsights.links) === null || _f === void 0 ? void 0 : _f.repository) ? { repository: packageInsights.links.repository } : {}),
                    ...(((_g = packageInsights.links) === null || _g === void 0 ? void 0 : _g.homepage) ? { homepage: packageInsights.links.homepage } : {}),
                    ...(((_h = packageInsights.links) === null || _h === void 0 ? void 0 : _h.bugs) ? { bugs: packageInsights.links.bugs } : {})
                }
            },
            compliance: {
                license: licenseInfo.record,
                licenseRisk
            },
            security: {
                summary: {
                    critical: vulnerabilities.counts.critical,
                    high: vulnerabilities.counts.high,
                    moderate: vulnerabilities.counts.moderate,
                    low: vulnerabilities.counts.low,
                    highest: vulnerabilities.highestSeverity,
                    risk: vulnerabilities.risk
                },
                ...(vulnerabilities.advisories && vulnerabilities.advisories.length > 0 ? { advisories: vulnerabilities.advisories } : {})
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
                ...(subDeps ? { subDeps } : {})
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
        schemaVersion: '1.2',
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
            minRequiredMajor: minRequiredMajor !== null && minRequiredMajor !== void 0 ? minRequiredMajor : 0,
            ...(input.platform ? { platform: input.platform } : {}),
            ...(input.arch ? { arch: input.arch } : {}),
            ...(typeof input.ci === 'boolean' ? { ci: input.ci } : {}),
            ...(input.packageManagerField ? { packageManagerField: input.packageManagerField } : {}),
            ...(input.packageManager ? { packageManager: input.packageManager } : {}),
            ...(input.packageManagerVersion ? { packageManagerVersion: input.packageManagerVersion } : {}),
            ...(input.toolVersions ? { toolVersions: input.toolVersions } : {})
        },
        workspaces: {
            enabled: input.workspaceEnabled,
            ...(input.workspaceType ? { type: input.workspaceType } : {}),
            ...(typeof input.workspacePackageCount === 'number'
                ? { packageCount: input.workspacePackageCount }
                : {})
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
function buildNodeMap(lsData) {
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
                childByName: new Map(),
                dev: node.dev,
                path: typeof node.path === 'string' ? node.path : undefined
            });
        }
        else {
            const existing = map.get(key);
            existing.depth = Math.min(existing.depth, depth);
            if (parentKey)
                existing.parents.add(parentKey);
            if (existing.dev === undefined && node.dev !== undefined)
                existing.dev = node.dev;
            if (!existing.path && typeof node.path === 'string')
                existing.path = node.path;
            if (!existing.children)
                existing.children = new Set();
            if (!existing.childByName)
                existing.childByName = new Map();
        }
        if (node.dependencies && typeof node.dependencies === 'object') {
            Object.entries(node.dependencies).forEach(([depName, child]) => {
                const childVersion = (child === null || child === void 0 ? void 0 : child.version) || 'unknown';
                const childKey = `${depName}@${childVersion}`;
                const current = map.get(key);
                if (current) {
                    current.children.add(childKey);
                    current.childByName.set(depName, childKey);
                }
                traverse(child, depth + 1, key, depName);
            });
        }
    };
    if (lsData && lsData.dependencies) {
        Object.entries(lsData.dependencies).forEach(([depName, child]) => traverse(child, 1, undefined, depName));
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
const GHSA_ID_REGEX = /GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}/i;
function extractGhsaId(value) {
    if (typeof value !== 'string')
        return undefined;
    const match = value.match(GHSA_ID_REGEX);
    return match ? match[0].toUpperCase() : undefined;
}
function extractNpmAdvisoryId(url) {
    const match = url.match(/advisories\/(\d+)/i);
    return match ? match[1] : undefined;
}
function resolveAdvisoryId(advisory, fallbackUrl) {
    const ghsa = extractGhsaId(advisory === null || advisory === void 0 ? void 0 : advisory.github_advisory_id) ||
        extractGhsaId(advisory === null || advisory === void 0 ? void 0 : advisory.ghsaId) ||
        extractGhsaId(advisory === null || advisory === void 0 ? void 0 : advisory.ghsa_id) ||
        extractGhsaId(advisory === null || advisory === void 0 ? void 0 : advisory.source) ||
        extractGhsaId(advisory === null || advisory === void 0 ? void 0 : advisory.id) ||
        extractGhsaId(advisory === null || advisory === void 0 ? void 0 : advisory.url) ||
        (fallbackUrl ? extractGhsaId(fallbackUrl) : undefined);
    if (ghsa)
        return ghsa;
    const url = typeof (advisory === null || advisory === void 0 ? void 0 : advisory.url) === 'string' ? advisory.url : undefined;
    const npmId = url ? extractNpmAdvisoryId(url) : undefined;
    if (npmId)
        return npmId;
    if ((advisory === null || advisory === void 0 ? void 0 : advisory.source) !== undefined)
        return String(advisory.source);
    if ((advisory === null || advisory === void 0 ? void 0 : advisory.id) !== undefined)
        return String(advisory.id);
    return undefined;
}
function resolveAdvisoryUrl(advisory, id) {
    if (typeof (advisory === null || advisory === void 0 ? void 0 : advisory.url) === 'string' && advisory.url.trim())
        return advisory.url.trim();
    if (id) {
        if (/^GHSA-/i.test(id))
            return `https://github.com/advisories/${id}`;
        if (/^\d+$/.test(id))
            return `https://www.npmjs.com/advisories/${id}`;
    }
    return undefined;
}
function resolveFixAvailable(value, patchedVersions) {
    if (typeof value === 'boolean')
        return value;
    if (value && typeof value === 'object')
        return true;
    if (typeof patchedVersions === 'string') {
        const trimmed = patchedVersions.trim();
        return Boolean(trimmed && trimmed !== '<0.0.0');
    }
    return false;
}
function normalizeAdvisoryRange(value) {
    if (typeof value === 'string' && value.trim())
        return value.trim();
    return 'unknown';
}
function buildAdvisoryFromVia(via, item) {
    var _a;
    if (!via || typeof via !== 'object')
        return undefined;
    const id = resolveAdvisoryId(via, via.url) || resolveAdvisoryId(item, item === null || item === void 0 ? void 0 : item.url);
    const title = typeof via.title === 'string' && via.title.trim()
        ? via.title.trim()
        : typeof via.name === 'string' && via.name.trim()
            ? via.name.trim()
            : 'Advisory';
    const severity = normalizeSeverity(via.severity || (item === null || item === void 0 ? void 0 : item.severity));
    const vulnerableRange = normalizeAdvisoryRange(via.range || via.vulnerable_versions || (item === null || item === void 0 ? void 0 : item.range));
    const fixAvailable = resolveFixAvailable((_a = via.fixAvailable) !== null && _a !== void 0 ? _a : item === null || item === void 0 ? void 0 : item.fixAvailable, via.patched_versions);
    const url = resolveAdvisoryUrl(via, id) || resolveAdvisoryUrl(item, id);
    if (!id)
        return undefined;
    return {
        id,
        title,
        severity,
        vulnerableRange,
        fixAvailable,
        url: url || ''
    };
}
function buildAdvisoryFromLegacy(adv) {
    if (!adv || typeof adv !== 'object')
        return undefined;
    const id = resolveAdvisoryId(adv, adv.url);
    const title = typeof adv.title === 'string' && adv.title.trim()
        ? adv.title.trim()
        : typeof adv.module_name === 'string' && adv.module_name.trim()
            ? adv.module_name.trim()
            : 'Advisory';
    const severity = normalizeSeverity(adv.severity);
    const vulnerableRange = normalizeAdvisoryRange(adv.vulnerable_versions || adv.vulnerableRange || adv.range);
    const fixAvailable = resolveFixAvailable(adv.fix_available, adv.patched_versions);
    const url = resolveAdvisoryUrl(adv, id);
    if (!id)
        return undefined;
    return {
        id,
        title,
        severity,
        vulnerableRange,
        fixAvailable,
        url: url || ''
    };
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
    const advisoryKeys = new Map();
    const deferredViaStrings = [];
    const addAdvisory = (name, advisory) => {
        const entry = ensureEntry(name);
        const key = `${advisory.id}|${advisory.vulnerableRange}`;
        let keys = advisoryKeys.get(name);
        if (!keys) {
            keys = new Set();
            advisoryKeys.set(name, keys);
        }
        if (keys.has(key))
            return;
        keys.add(key);
        if (!entry.advisories)
            entry.advisories = [];
        entry.advisories.push(advisory);
    };
    // Advisories are disclosed findings from npm audit (not malware detection).
    // Summary-only output loses evidence and is a data loss bug.
    if (auditData.vulnerabilities) {
        Object.values(auditData.vulnerabilities).forEach((item) => {
            const name = item.name || 'unknown';
            const viaList = Array.isArray(item.via) ? item.via : [];
            let added = false;
            for (const via of viaList) {
                if (via && typeof via === 'object') {
                    const advisory = buildAdvisoryFromVia(via, item);
                    if (advisory) {
                        addAdvisory(name, advisory);
                        added = true;
                    }
                }
            }
            const viaStrings = viaList.filter((via) => typeof via === 'string');
            if (viaStrings.length > 0) {
                deferredViaStrings.push({ name, via: viaStrings });
            }
            if (!added) {
                const fallback = buildAdvisoryFromVia(item, item);
                if (fallback)
                    addAdvisory(name, fallback);
            }
        });
    }
    if (auditData.advisories) {
        Object.values(auditData.advisories).forEach((adv) => {
            const name = adv.module_name || adv.module || 'unknown';
            const advisory = buildAdvisoryFromLegacy(adv);
            if (advisory)
                addAdvisory(name, advisory);
        });
    }
    // One-level expansion: map string "via" references to their advisories without storing paths.
    for (const entry of deferredViaStrings) {
        for (const refName of entry.via) {
            const referenced = map.get(refName);
            if (referenced === null || referenced === void 0 ? void 0 : referenced.advisories) {
                for (const advisory of referenced.advisories) {
                    addAdvisory(entry.name, advisory);
                }
            }
        }
    }
    map.forEach((entry) => {
        const counts = { low: 0, moderate: 0, high: 0, critical: 0 };
        if (entry.advisories) {
            for (const advisory of entry.advisories) {
                counts[advisory.severity] += 1;
            }
        }
        entry.counts = counts;
        entry.highestSeverity = computeHighestSeverity(counts);
        entry.risk = (0, utils_1.vulnRiskLevel)(counts);
        if (entry.advisories && entry.advisories.length > 0) {
            entry.advisories.sort((a, b) => {
                const order = { critical: 4, high: 3, moderate: 2, low: 1 };
                const diff = order[b.severity] - order[a.severity];
                if (diff !== 0)
                    return diff;
                return a.title.localeCompare(b.title);
            });
        }
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
        highestSeverity: 'none',
        risk: 'green'
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
            category: classifyFileCategory(file)
        }));
        // Rank: prefer non-testing files, then higher import counts, then closer to root.
        entries.sort((a, b) => {
            const aIsTest = a.category === 'testing';
            const bIsTest = b.category === 'testing';
            if (aIsTest !== bIsTest)
                return aIsTest ? 1 : -1;
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
        runtimeImpact.set(dep, determineRuntimeImpactFromFiles(entries));
    }
    return { summary, runtimeImpact };
}
function isDirectDependency(name, pkg) {
    return Boolean((pkg.dependencies && pkg.dependencies[name]) ||
        (pkg.devDependencies && pkg.devDependencies[name]) ||
        (pkg.optionalDependencies && pkg.optionalDependencies[name]) ||
        (pkg.peerDependencies && pkg.peerDependencies[name]));
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
        const scope = directScopeFromPackage(root.name, pkg);
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
function buildSubDeps(declared, node) {
    const out = {};
    const entries = [
        ['dep', 'dep'],
        ['dev', 'dev'],
        ['opt', 'opt'],
        ['peer', 'peer']
    ];
    for (const [declaredKey, outKey] of entries) {
        const group = declared[declaredKey];
        const names = Object.keys(group);
        if (names.length === 0)
            continue;
        const bucket = {};
        for (const name of names.sort()) {
            const range = group[name];
            const resolved = node.childByName.get(name) || null;
            bucket[name] = [range, resolved];
        }
        if (Object.keys(bucket).length > 0) {
            out[outKey] = bucket;
        }
    }
    return Object.keys(out).length > 0 ? out : undefined;
}
function buildOrigins(rootCauses, parentIds, workspaceList, workspaceEnabled, maxTopRoots, maxTopParents) {
    const origins = {
        rootPackageCount: rootCauses.length,
        topRootPackages: rootCauses.slice(0, maxTopRoots),
        parentPackageCount: parentIds.length,
        topParentPackages: parentIds.slice(0, maxTopParents)
    };
    if (workspaceEnabled && workspaceList && workspaceList.length > 0) {
        origins.workspaces = workspaceList;
    }
    return origins;
}
function isTestFile(file) {
    return (/(^|\/)(__tests__|__mocks__|test|tests|testing|e2e|cypress|playwright|__snapshots__)(\/|$)/.test(file) ||
        /\.(test|spec|e2e)\./.test(file) ||
        /(^|\/)(jest|vitest|playwright|cypress)\.config\./.test(file) ||
        /(^|\/)\.(jest|vitest|playwright|cypress)(rc|\.config)?(\..*)?$/.test(file));
}
function isToolingFile(file) {
    return (/(^|\/)(eslint|prettier|stylelint|commitlint|lint-staged|husky|renovate|semantic-release|release-it|lefthook|dependabot)[^\/]*\./.test(file) ||
        /(^|\/)\.(eslint|eslintrc|prettier|prettierrc|stylelint|stylelintrc|commitlint|commitlintrc|lint-staged|lintstagedrc|husky|huskyrc|renovate|semantic-release|release-it|lefthook|dependabot)(rc|\.config)?(\..*)?$/.test(file));
}
function isBuildFile(file) {
    return (/(^|\/)(webpack|rollup|vite|tsconfig|babel|swc|esbuild|parcel|gulpfile|gruntfile|postcss|tailwind|storybook|rspack|turbo|nx|metro)[^\/]*\./.test(file) ||
        /(^|\/)scripts\/(build|bundle|compile|release|deploy)(\/|\.|$)/.test(file) ||
        /(^|\/)\.(webpack|rollup|vite|tsconfig|babel|babelrc|swc|swcrc|esbuild|parcel|postcss|postcssrc|tailwind|storybook|rspack|turbo|nx|metro)(rc|\.config)?(\..*)?$/.test(file));
}
function classifyFileCategory(file) {
    if (isTestFile(file))
        return 'testing';
    if (isToolingFile(file))
        return 'tooling';
    if (isBuildFile(file))
        return 'build';
    return 'runtime';
}
function determineRuntimeImpactFromFiles(files) {
    const weights = {
        runtime: 0,
        build: 0,
        testing: 0,
        tooling: 0
    };
    let total = 0;
    for (const entry of files) {
        const category = classifyFileCategory(entry.file);
        const weight = Number.isFinite(entry.count) && entry.count > 0 ? entry.count : 1;
        weights[category] += weight;
        total += weight;
    }
    if (total <= 0)
        return 'runtime';
    const ranked = Object.entries(weights)
        .filter(([, weight]) => weight > 0)
        .sort((a, b) => b[1] - a[1]);
    if (ranked.length === 0)
        return 'runtime';
    if (ranked.length === 1)
        return ranked[0][0];
    const [top, second] = ranked;
    const topRatio = top[1] / total;
    const secondRatio = second ? second[1] / total : 0;
    // Strong dominance: classify as a single category instead of defaulting to mixed.
    if (topRatio >= 0.7)
        return top[0];
    // Runtime is common; tolerate a small amount of non-runtime usage before calling it mixed.
    if (top[0] === 'runtime' && topRatio >= 0.6 && secondRatio <= 0.25)
        return 'runtime';
    // Testing-heavy dependencies often leak a small runtime footprint (helpers in fixtures).
    if (top[0] === 'testing' && topRatio >= 0.6 && secondRatio <= 0.3)
        return 'testing';
    return 'mixed';
}
function buildLicenseInfo(declaredRaw, licenseText) {
    const declaredValue = typeof declaredRaw === 'string' ? declaredRaw.trim() : '';
    const hasDeclared = Boolean(declaredValue);
    const declaredValidation = hasDeclared ? (0, license_1.validateSpdxExpression)(declaredValue) : undefined;
    const inferred = licenseText ? (0, license_1.inferLicenseFromText)(licenseText) : undefined;
    const record = {
        status: 'unknown'
    };
    if (hasDeclared && declaredValidation) {
        record.declared = {
            spdxId: declaredValidation.normalized || declaredValue,
            expression: declaredValidation.expression,
            deprecated: declaredValidation.deprecated,
            valid: declaredValidation.valid
        };
        if (declaredValidation.exceptions.length === 1) {
            record.exception = declaredValidation.exceptions[0];
        }
    }
    if (inferred) {
        record.inferred = {
            spdxId: inferred.spdxId,
            confidence: inferred.confidence
        };
    }
    if (hasDeclared && declaredValidation && !declaredValidation.valid) {
        record.status = 'invalid-spdx';
    }
    else if ((declaredValidation === null || declaredValidation === void 0 ? void 0 : declaredValidation.valid) && inferred) {
        record.status = declaredValidation.normalized === inferred.spdxId ? 'match' : 'mismatch';
    }
    else if (declaredValidation === null || declaredValidation === void 0 ? void 0 : declaredValidation.valid) {
        record.status = 'declared-only';
    }
    else if (inferred) {
        record.status = 'inferred-only';
    }
    else {
        record.status = 'unknown';
    }
    if (declaredValidation === null || declaredValidation === void 0 ? void 0 : declaredValidation.valid) {
        return { record, licenseIds: declaredValidation.licenseIds };
    }
    if (inferred) {
        return { record, licenseIds: [inferred.spdxId] };
    }
    return { record, licenseIds: [] };
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
function determineIntroduction(direct, scope, rootCauses, runtimeImpact) {
    const rootNames = rootCauses.map((root) => root.name);
    if (direct)
        return 'direct';
    if (runtimeImpact === 'testing')
        return 'testing';
    if (runtimeImpact === 'tooling' || runtimeImpact === 'build')
        return 'tooling';
    if (scope === 'dev' || scope === 'peer')
        return 'tooling';
    if (rootNames.length > 0 && rootNames.every((root) => isToolingPackage(root)))
        return 'tooling';
    if (rootNames.some((root) => isFrameworkPackage(root)))
        return 'framework';
    if (rootNames.length > 0)
        return 'transitive';
    return 'unknown';
}
// Upgrade blockers derived only from local metadata (no external lookups).
function buildUpgradeBlock(insights) {
    var _a;
    const blockers = [];
    if (insights.nodeEngine)
        blockers.push('nodeEngine');
    if (Object.keys(insights.declaredDependencies.peer).length > 0)
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
async function gatherPackageInsights(name, version, resolvePaths, metaCache, statCache) {
    var _a;
    const meta = await loadPackageMeta(name, resolvePaths, metaCache, version);
    if (!meta) {
        return {
            deprecated: false,
            nodeEngine: null,
            hasBin: false,
            declaredDependencies: { dep: {}, dev: {}, peer: {}, opt: {} },
            tsTypes: 'unknown'
        };
    }
    const pkg = (meta === null || meta === void 0 ? void 0 : meta.pkg) || {};
    const dir = meta === null || meta === void 0 ? void 0 : meta.dir;
    const stats = dir ? await calculatePackageStats(dir, statCache) : undefined;
    const declaredDependencies = {
        dep: normalizeDeclaredDeps(pkg.dependencies),
        dev: normalizeDeclaredDeps(pkg.devDependencies),
        peer: normalizeDeclaredDeps(pkg.peerDependencies),
        opt: normalizeDeclaredDeps(pkg.optionalDependencies)
    };
    const scripts = pkg.scripts || {};
    const deprecated = Boolean(pkg.deprecated);
    const nodeEngine = typeof ((_a = pkg.engines) === null || _a === void 0 ? void 0 : _a.node) === 'string' ? pkg.engines.node : null;
    const description = typeof pkg.description === 'string' && pkg.description.trim()
        ? pkg.description.trim()
        : undefined;
    const hasBin = hasPackageBin(pkg.bin);
    const hasDefinitelyTyped = await hasDefinitelyTypedPackage(name, resolvePaths, metaCache);
    const tsTypes = determineTypes(pkg, (stats === null || stats === void 0 ? void 0 : stats.hasDts) || false, hasDefinitelyTyped);
    const links = extractPackageLinks(pkg);
    const execution = await deriveExecutionInfo(scripts, dir, stats);
    return {
        deprecated,
        nodeEngine,
        description,
        ...(typeof (stats === null || stats === void 0 ? void 0 : stats.fileCount) === 'number' ? { fileCount: stats.fileCount } : {}),
        hasBin,
        declaredDependencies,
        links,
        execution,
        tsTypes
    };
}
function normalizeDeclaredDeps(source) {
    if (!source || typeof source !== 'object')
        return {};
    const out = {};
    for (const [name, range] of Object.entries(source)) {
        if (typeof name !== 'string' || !name.trim())
            continue;
        if (typeof range !== 'string' || !range.trim())
            continue;
        out[name] = range.trim();
    }
    return out;
}
function hasPackageBin(binField) {
    if (typeof binField === 'string')
        return binField.trim().length > 0;
    if (!binField || typeof binField !== 'object')
        return false;
    return Object.values(binField).some((value) => typeof value === 'string' && value.trim().length > 0);
}
async function loadPackageMeta(name, resolvePaths, cache, version) {
    const cacheKey = version ? `${name}@${version}` : name;
    if (cache.has(cacheKey))
        return cache.get(cacheKey);
    try {
        const pkgJsonPath = await (0, utils_1.resolvePackageJsonPath)(name, resolvePaths, version);
        if (!pkgJsonPath)
            return undefined;
        const pkgRaw = await promises_1.default.readFile(pkgJsonPath, 'utf8');
        const pkg = JSON.parse(pkgRaw);
        const meta = { pkg, dir: path_1.default.dirname(pkgJsonPath) };
        cache.set(cacheKey, meta);
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
async function hasDefinitelyTypedPackage(name, resolvePaths, cache) {
    if (name.startsWith('@types/'))
        return true;
    const typesName = toDefinitelyTypedPackageName(name);
    if (!typesName)
        return false;
    const meta = await loadPackageMeta(typesName, resolvePaths, cache);
    return Boolean(meta);
}
async function calculatePackageStats(dir, cache) {
    if (cache.has(dir))
        return cache.get(dir);
    let hasDts = false;
    let hasNativeBinary = false;
    let hasBindingGyp = false;
    let fileCount = 0;
    async function walk(current) {
        const entries = await promises_1.default.readdir(current, { withFileTypes: true });
        for (const entry of entries) {
            const full = path_1.default.join(current, entry.name);
            if (entry.isSymbolicLink())
                continue;
            if (entry.isDirectory()) {
                // Ignore nested dependency stores to keep package-level stats bounded and comparable.
                if (entry.name === 'node_modules' || entry.name === '.git')
                    continue;
                await walk(full);
            }
            else if (entry.isFile()) {
                fileCount += 1;
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
    const result = { hasDts, hasNativeBinary, hasBindingGyp, fileCount };
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
