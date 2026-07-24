"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.aggregateData = aggregateData;
exports.detectLocalExecutionSignals = detectLocalExecutionSignals;
exports.collectPackageExecutionSignals = collectPackageExecutionSignals;
const utils_1 = require("./utils");
const license_1 = require("./license");
const findings_1 = require("./findings");
const nodeEngine_1 = require("./nodeEngine");
const upgradeRisk_1 = require("./upgradeRisk");
const replacements_1 = require("./generated/replacements");
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
function findRootCauses(node, nodeMap) {
    // If it's a direct dependency, it's its own root cause
    if (node.isDirect) {
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
        if (parent.isDirect) {
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
function asTrimmedString(value) {
    if (typeof value !== 'string')
        return undefined;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
}
function normalizeStringList(value) {
    if (typeof value === 'string') {
        const single = value.trim();
        return single ? [single] : undefined;
    }
    if (!Array.isArray(value))
        return undefined;
    const items = value
        .map((entry) => (typeof entry === 'string' ? entry.trim() : ''))
        .filter(Boolean);
    if (items.length === 0)
        return undefined;
    return Array.from(new Set(items));
}
function toObjectRecord(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return undefined;
    return value;
}
function hasKeys(value) {
    return Boolean(value && Object.keys(value).length > 0);
}
function mergeRecordObjects(...sources) {
    const merged = {};
    for (const source of sources) {
        if (!source)
            continue;
        for (const [key, val] of Object.entries(source)) {
            merged[key] = val;
        }
    }
    return Object.keys(merged).length > 0 ? merged : undefined;
}
function normalizeRepository(repository) {
    const direct = asTrimmedString(repository);
    if (direct)
        return direct;
    const asObject = toObjectRecord(repository);
    if (!asObject)
        return undefined;
    const url = asTrimmedString(asObject.url);
    if (url)
        return url;
    const type = asTrimmedString(asObject.type);
    const directory = asTrimmedString(asObject.directory);
    if (type && directory)
        return `${type} (${directory})`;
    return type;
}
function extractPackageNameFromSelector(selector) {
    let token = selector.trim();
    if (!token)
        return undefined;
    if (token.includes('>')) {
        const parts = token.split('>').map((part) => part.trim()).filter(Boolean);
        if (parts.length > 0)
            token = parts[parts.length - 1];
    }
    if (token.startsWith('npm:')) {
        token = token.slice(4).trim();
    }
    if (!token)
        return undefined;
    if (token.startsWith('@')) {
        const scopedMatch = token.match(/^@[^/\s]+\/[^@\s]+/);
        return scopedMatch ? scopedMatch[0] : undefined;
    }
    const atIndex = token.indexOf('@');
    const unversioned = atIndex > 0 ? token.slice(0, atIndex) : token;
    const match = unversioned.match(/^[^@\s]+/);
    return match ? match[0] : undefined;
}
function collectPolicyPackageNames(entries) {
    if (!entries)
        return undefined;
    const names = new Set();
    for (const selector of Object.keys(entries)) {
        const pkgName = extractPackageNameFromSelector(selector);
        if (pkgName)
            names.add(pkgName);
    }
    if (names.size === 0)
        return undefined;
    return Array.from(names).sort();
}
function buildProjectDependencyPolicy(projectPkg, inputPolicy) {
    var _a;
    const projectPkgOverrides = toObjectRecord(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.overrides);
    const projectPkgPnpm = toObjectRecord(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.pnpm);
    const projectPkgPnpmOverrides = toObjectRecord(projectPkgPnpm === null || projectPkgPnpm === void 0 ? void 0 : projectPkgPnpm.overrides);
    const projectPkgResolutions = toObjectRecord(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.resolutions);
    const overrides = mergeRecordObjects(projectPkgOverrides, projectPkgPnpmOverrides, inputPolicy === null || inputPolicy === void 0 ? void 0 : inputPolicy.overrides);
    const resolutions = mergeRecordObjects(projectPkgResolutions, inputPolicy === null || inputPolicy === void 0 ? void 0 : inputPolicy.resolutions);
    const sources = new Set();
    if (hasKeys(projectPkgOverrides))
        sources.add('package.json#overrides');
    if (hasKeys(projectPkgPnpmOverrides))
        sources.add('package.json#pnpm.overrides');
    if (hasKeys(projectPkgResolutions))
        sources.add('package.json#resolutions');
    (_a = inputPolicy === null || inputPolicy === void 0 ? void 0 : inputPolicy.sources) === null || _a === void 0 ? void 0 : _a.forEach((source) => {
        const normalized = source.trim();
        if (normalized)
            sources.add(normalized);
    });
    const policy = {
        ...(overrides ? { overrides } : {}),
        ...(resolutions ? { resolutions } : {})
    };
    return {
        ...(hasKeys(policy.overrides) || hasKeys(policy.resolutions) ? { policy } : {}),
        ...(sources.size > 0 ? { sources: Array.from(sources).sort() } : {})
    };
}
function buildProjectDependencyPolicySummary(policy, sources) {
    const overrideCount = (policy === null || policy === void 0 ? void 0 : policy.overrides) ? Object.keys(policy.overrides).length : 0;
    const resolutionCount = (policy === null || policy === void 0 ? void 0 : policy.resolutions) ? Object.keys(policy.resolutions).length : 0;
    if (overrideCount === 0 && resolutionCount === 0)
        return undefined;
    const overriddenPackageNames = collectPolicyPackageNames(policy === null || policy === void 0 ? void 0 : policy.overrides);
    const resolvedPackageNames = collectPolicyPackageNames(policy === null || policy === void 0 ? void 0 : policy.resolutions);
    return {
        hasOverrides: overrideCount > 0,
        overrideCount,
        ...(overriddenPackageNames ? { overriddenPackageNames } : {}),
        hasResolutions: resolutionCount > 0,
        resolutionCount,
        ...(resolvedPackageNames ? { resolvedPackageNames } : {}),
        ...(sources && sources.length > 0 ? { sources } : {})
    };
}
function buildProjectMetadata(projectPath, projectPkg, inputPolicy) {
    var _a, _b;
    const { policy, sources } = buildProjectDependencyPolicy(projectPkg, inputPolicy);
    const policySummary = buildProjectDependencyPolicySummary(policy, sources);
    const constraints = {
        ...(normalizeStringList(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.os) ? { os: normalizeStringList(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.os) } : {}),
        ...(normalizeStringList(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.cpu) ? { cpu: normalizeStringList(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.cpu) } : {}),
        ...(asTrimmedString((_a = projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.engines) === null || _a === void 0 ? void 0 : _a.node) ? { enginesNode: asTrimmedString((_b = projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.engines) === null || _b === void 0 ? void 0 : _b.node) } : {})
    };
    const hasConstraints = Object.keys(constraints).length > 0;
    return {
        projectDir: formatProjectDir(projectPath),
        ...(asTrimmedString(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.name) ? { name: asTrimmedString(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.name) } : {}),
        ...(asTrimmedString(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.version) ? { version: asTrimmedString(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.version) } : {}),
        ...(asTrimmedString(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.description) ? { description: asTrimmedString(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.description) } : {}),
        ...(asTrimmedString(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.license) ? { license: asTrimmedString(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.license) } : {}),
        ...(normalizeStringList(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.keywords) ? { keywords: normalizeStringList(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.keywords) } : {}),
        ...(asTrimmedString(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.homepage) ? { homepage: asTrimmedString(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.homepage) } : {}),
        ...(normalizeRepository(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.repository) ? { repository: normalizeRepository(projectPkg === null || projectPkg === void 0 ? void 0 : projectPkg.repository) } : {}),
        ...(hasConstraints ? { constraints } : {}),
        ...(policy ? { dependencyPolicy: policy } : {}),
        ...(policySummary ? { dependencyPolicySummary: policySummary } : {})
    };
}
function getRiskRank(risk) {
    if (risk === 'red')
        return 2;
    if (risk === 'amber')
        return 1;
    return 0;
}
function maxRisk(...risks) {
    let highest = 'green';
    for (const risk of risks) {
        if (getRiskRank(risk) > getRiskRank(highest))
            highest = risk;
    }
    return highest;
}
function resolveLicenseRisk(licenseInfo) {
    const declaredOrPrimaryRisk = (0, license_1.pickLicenseRisk)(licenseInfo.licenseIds);
    if (licenseInfo.record.status !== 'mismatch')
        return declaredOrPrimaryRisk;
    const inferredRisk = licenseInfo.record.inferred
        ? (0, license_1.pickLicenseRisk)([licenseInfo.record.inferred.spdxId])
        : 'green';
    return maxRisk(declaredOrPrimaryRisk, inferredRisk, 'amber');
}
function isWorkspaceLocalVersion(version) {
    const normalized = version.trim().toLowerCase();
    return normalized.startsWith('workspace:') || normalized.startsWith('link:') || normalized.startsWith('file:');
}
function isPathWithin(basePath, candidatePath) {
    const normalizedBase = path_1.default.resolve(basePath);
    const normalizedCandidate = path_1.default.resolve(candidatePath);
    return (normalizedCandidate === normalizedBase ||
        normalizedCandidate.startsWith(`${normalizedBase}${path_1.default.sep}`));
}
function isWorkspacePackageNode(node, input) {
    var _a, _b, _c;
    if (!input.workspaceEnabled)
        return false;
    if ((_a = input.workspacePackageIds) === null || _a === void 0 ? void 0 : _a.has(node.key))
        return true;
    if (isWorkspaceLocalVersion(node.version))
        return true;
    if ((_b = input.workspaceLocalDependencyNames) === null || _b === void 0 ? void 0 : _b.has(node.name))
        return true;
    if (node.path && input.workspacePackagePaths && input.workspacePackagePaths.size > 0) {
        for (const workspacePath of input.workspacePackagePaths) {
            if (isPathWithin(workspacePath, node.path))
                return true;
        }
    }
    if (((_c = input.workspacePackageNames) === null || _c === void 0 ? void 0 : _c.has(node.name)) && node.depth <= 1) {
        return true;
    }
    return false;
}
/**
 * Builds a consolidated AggregatedData object for a dependency and audit scan.
 *
 * Combines package metadata, dependency graph structure, vulnerability summaries,
 * import/usage data, outdated status, supply-chain signals, and per-dependency
 * heuristics (license, execution/installation scripts, packaging, types support,
 * links, peer requirements, and upgrade blockers) into a single summary object.
 *
 * @param input - All inputs and options required to perform aggregation (tool outputs, workspace/configuration, resolution paths, platform/runtime metadata, and optional policy overrides).
 * @returns The assembled AggregatedData containing project metadata, environment info, per-dependency records, findings, and summary counts.
 */
async function aggregateData(input) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j;
    const pkg = input.pkgOverride || (await (0, utils_1.readPackageJson)(input.projectPath));
    let projectPkg = input.projectPackageJson;
    if (!projectPkg) {
        try {
            projectPkg = await (0, utils_1.readPackageJson)(input.projectPath);
        }
        catch {
            projectPkg = {};
        }
    }
    const project = buildProjectMetadata(input.projectPath, projectPkg, input.projectDependencyPolicy);
    // Get git branch
    const gitBranch = await getGitBranch(input.projectPath);
    const nodeMap = buildNodeMap((_a = input.npmLsResult) === null || _a === void 0 ? void 0 : _a.data, Boolean(input.workspaceEnabled));
    for (const node of nodeMap.values()) {
        node.isDirect = node.importerChild && isDirectDependency(node.name, pkg);
    }
    const vulnerabilityIndex = parseVulnerabilities((_b = input.auditResult) === null || _b === void 0 ? void 0 : _b.data);
    const importGraph = normalizeImportGraph((_c = input.importGraphResult) === null || _c === void 0 ? void 0 : _c.data);
    const usageResult = buildUsageSummary(importGraph, input.projectPath);
    const outdatedById = buildOutdatedMap(input.outdatedResult);
    const supplyChain = normalizeSupplyChain((_d = input.supplyChainResult) === null || _d === void 0 ? void 0 : _d.data);
    const outdatedUnknownNames = new Set(((_e = input.outdatedResult) === null || _e === void 0 ? void 0 : _e.unknownNames) || []);
    const packageMetaCache = new Map();
    const resolvePaths = input.resolvePaths && input.resolvePaths.length > 0
        ? input.resolvePaths
        : [input.projectPath];
    const packageStatCache = new Map();
    const dependencies = {};
    const licenseCache = new Map();
    const nodeEngineRanges = [];
    const nodes = Array.from(nodeMap.values()).filter((node) => !isWorkspacePackageNode(node, input));
    let directCount = 0;
    const MAX_TOP_ROOT_PACKAGES = 10; // cap to keep payload size predictable
    const MAX_TOP_PARENT_PACKAGES = 5; // cap for direct parents to keep payload size predictable
    for (const node of nodes) {
        const direct = node.isDirect;
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
        const vulnerabilities = vulnerabilitiesForNode(vulnerabilityIndex, node);
        const licenseInfo = buildLicenseInfo(licenseSource.license, licenseSource.licenseText);
        const licenseRisk = resolveLicenseRisk(licenseInfo);
        // Calculate root causes (direct dependencies that cause this to be installed)
        const rootCauses = findRootCauses(node, nodeMap);
        const packageInsights = await gatherPackageInsights(node.name, node.version, resolvePaths, packageMetaCache, packageStatCache);
        if (packageInsights.nodeEngine) {
            nodeEngineRanges.push(packageInsights.nodeEngine);
        }
        const scope = determineScope(node.name, direct, rootCauses, pkg);
        const importUsage = usageResult.summary.get(node.name);
        const runtimeImpact = usageResult.runtimeImpact.get(node.name);
        const introduction = determineIntroduction(direct, scope, rootCauses, runtimeImpact);
        const parentIds = Array.from(node.parents).sort();
        const origins = buildOrigins(rootCauses, parentIds, (_f = input.workspaceUsage) === null || _f === void 0 ? void 0 : _f.get(node.name), input.workspaceEnabled, MAX_TOP_ROOT_PACKAGES, MAX_TOP_PARENT_PACKAGES);
        const execution = packageInsights.execution;
        const packaging = packageInsights.packaging;
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
            ...((upgrade === null || upgrade === void 0 ? void 0 : upgrade.blocksNodeMajor) ? { blocksNodeMajor: upgrade.blocksNodeMajor } : {}),
            ...(typeof input.targetNodeMajor === 'number' && packageInsights.nodeEngine
                ? { targetNodeCompatible: (0, nodeEngine_1.isNodeEngineTargetCompatible)(packageInsights.nodeEngine, input.targetNodeMajor) }
                : {})
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
                    ...(((_g = packageInsights.links) === null || _g === void 0 ? void 0 : _g.repository) ? { repository: packageInsights.links.repository } : {}),
                    ...(((_h = packageInsights.links) === null || _h === void 0 ? void 0 : _h.homepage) ? { homepage: packageInsights.links.homepage } : {}),
                    ...(((_j = packageInsights.links) === null || _j === void 0 ? void 0 : _j.bugs) ? { bugs: packageInsights.links.bugs } : {})
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
            ...(execution ? { execution } : {}),
            ...(packaging ? { packaging } : {})
        };
        // Offline lookup against the vendored e18e module-replacements catalogue.
        const replacementEntry = replacements_1.MODULE_REPLACEMENTS[node.name];
        if (replacementEntry) {
            dependencies[id].replacement = {
                source: 'e18e-module-replacements',
                manifest: replacementEntry.manifest,
                type: replacementEntry.type,
                replacements: replacementEntry.replacements,
                ...(replacementEntry.docUrl ? { docUrl: replacementEntry.docUrl } : {})
            };
        }
    }
    const minRequiredMajor = deriveMinRequiredMajor(nodeEngineRanges);
    const runtimeVersion = process.version;
    const nodeVersion = process.versions.node;
    const dependencyCount = nodes.length;
    const transitiveCount = dependencyCount - directCount;
    const aggregated = {
        schemaVersion: '1.7',
        generatedAt: new Date().toISOString(),
        dependencyRadarVersion,
        git: {
            branch: gitBranch || ''
        },
        project,
        environment: {
            nodeVersion,
            runtimeVersion,
            minRequiredMajor: minRequiredMajor !== null && minRequiredMajor !== void 0 ? minRequiredMajor : 0,
            ...(typeof input.targetNodeMajor === 'number' ? { targetNodeMajor: input.targetNodeMajor } : {}),
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
                : {}),
            ...(input.workspacePackages ? { workspacePackages: input.workspacePackages } : {})
        },
        summary: {
            dependencyCount,
            directCount,
            transitiveCount
        },
        ...(supplyChain ? { supplyChain } : {}),
        dependencies
    };
    (0, upgradeRisk_1.applyUpgradeRisk)(aggregated);
    const findings = (0, findings_1.buildDependencyFindings)(aggregated, { targetNodeMajor: input.targetNodeMajor });
    aggregated.findings = findings;
    aggregated.summary.findingCount = findings.length;
    return aggregated;
}
function normalizeSupplyChain(data) {
    if (!data || typeof data !== 'object')
        return undefined;
    const signals = Array.isArray(data.signals) ? data.signals : [];
    const signatureAudit = data.signatureAudit && typeof data.signatureAudit === 'object'
        ? data.signatureAudit
        : undefined;
    if (signals.length === 0 && !signatureAudit)
        return undefined;
    return {
        signals,
        ...(signatureAudit ? { signatureAudit } : {})
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
function buildNodeMap(lsData, workspaceMode = false) {
    const map = new Map();
    // In combined workspace graphs each workspace package is a synthetic depth-1
    // node, so the importer's real direct dependencies sit at traversal depth 2.
    const importerDepth = workspaceMode ? 2 : 1;
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
                path: typeof node.path === 'string' ? node.path : undefined,
                importerChild: depth === importerDepth,
                isDirect: false
            });
        }
        else {
            const existing = map.get(key);
            existing.depth = Math.min(existing.depth, depth);
            if (depth === importerDepth)
                existing.importerChild = true;
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
function summarizeAdvisories(advisories) {
    const sorted = [...advisories].sort((a, b) => {
        const order = { critical: 4, high: 3, moderate: 2, low: 1 };
        const diff = order[b.severity] - order[a.severity];
        if (diff !== 0)
            return diff;
        return a.title.localeCompare(b.title);
    });
    const counts = { low: 0, moderate: 0, high: 0, critical: 0 };
    for (const advisory of sorted)
        counts[advisory.severity] += 1;
    return {
        counts,
        highestSeverity: computeHighestSeverity(counts),
        risk: (0, utils_1.vulnRiskLevel)(counts),
        ...(sorted.length > 0 ? { advisories: sorted } : {})
    };
}
function vulnerabilitiesForNode(index, node) {
    if (node.path) {
        const pathMatch = index.byNodePath.get(path_1.default.resolve(node.path));
        if (pathMatch)
            return pathMatch;
        if (index.namesWithNodePaths.has(node.name))
            return emptyVulnSummary();
    }
    const packageIdMatch = index.byPackageId.get(node.key);
    if (packageIdMatch)
        return packageIdMatch;
    if (index.namesWithPackageIds.has(node.name))
        return emptyVulnSummary();
    return index.byName.get(node.name) || emptyVulnSummary();
}
function parseVulnerabilities(auditData) {
    const map = new Map();
    const nodePathsByName = new Map();
    const advisoriesByAuditKey = new Map();
    const advisoriesByNodePath = new Map();
    const advisoriesByPackageId = new Map();
    if (!auditData) {
        return {
            byName: map,
            byNodePath: new Map(),
            byPackageId: new Map(),
            namesWithNodePaths: new Set(),
            namesWithPackageIds: new Set(),
        };
    }
    const ensureEntry = (name) => {
        if (!map.has(name)) {
            map.set(name, emptyVulnSummary());
        }
        return map.get(name);
    };
    const advisoryKeys = new Map();
    const deferredViaStrings = [];
    const addAdvisoryToList = (target, key, advisory) => {
        const advisories = target.get(key) || [];
        if (!advisories.some((entry) => entry.id === advisory.id && entry.vulnerableRange === advisory.vulnerableRange)) {
            advisories.push(advisory);
        }
        target.set(key, advisories);
    };
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
        Object.entries(auditData.vulnerabilities).forEach(([auditKey, item]) => {
            const name = item.name || 'unknown';
            const nodePaths = Array.isArray(item.nodes)
                ? item.nodes
                    .filter((node) => typeof node === 'string' && node.trim().length > 0)
                    .map((node) => path_1.default.resolve(node))
                : [];
            if (nodePaths.length > 0) {
                const paths = nodePathsByName.get(name) || new Set();
                for (const nodePath of nodePaths)
                    paths.add(nodePath);
                nodePathsByName.set(name, paths);
            }
            const viaList = Array.isArray(item.via) ? item.via : [];
            const itemAdvisories = [];
            let added = false;
            for (const via of viaList) {
                if (via && typeof via === 'object') {
                    const advisory = buildAdvisoryFromVia(via, item);
                    if (advisory) {
                        addAdvisory(name, advisory);
                        itemAdvisories.push(advisory);
                        added = true;
                    }
                }
            }
            const viaStrings = viaList.filter((via) => typeof via === 'string');
            if (viaStrings.length > 0) {
                deferredViaStrings.push({ auditKey, name, nodePaths, via: viaStrings });
            }
            if (!added) {
                const fallback = buildAdvisoryFromVia(item, item);
                if (fallback) {
                    addAdvisory(name, fallback);
                    itemAdvisories.push(fallback);
                }
            }
            for (const advisory of itemAdvisories) {
                addAdvisoryToList(advisoriesByAuditKey, auditKey, advisory);
                for (const nodePath of nodePaths) {
                    addAdvisoryToList(advisoriesByNodePath, nodePath, advisory);
                }
            }
        });
    }
    if (auditData.advisories) {
        Object.values(auditData.advisories).forEach((adv) => {
            const name = adv.module_name || adv.module || 'unknown';
            const advisory = buildAdvisoryFromLegacy(adv);
            if (advisory) {
                addAdvisory(name, advisory);
                const findings = Array.isArray(adv.findings) ? adv.findings : [];
                for (const finding of findings) {
                    const version = typeof (finding === null || finding === void 0 ? void 0 : finding.version) === 'string' ? finding.version.trim() : '';
                    if (!version)
                        continue;
                    const packageId = `${name}@${version}`;
                    const advisories = advisoriesByPackageId.get(packageId) || [];
                    if (!advisories.some((entry) => entry.id === advisory.id && entry.vulnerableRange === advisory.vulnerableRange)) {
                        advisories.push(advisory);
                    }
                    advisoriesByPackageId.set(packageId, advisories);
                }
            }
        });
    }
    // One-level expansion: map string "via" references to their advisories while preserving paths.
    for (const entry of deferredViaStrings) {
        for (const refName of entry.via) {
            const referenced = advisoriesByAuditKey.get(refName);
            if (referenced) {
                for (const advisory of referenced) {
                    addAdvisory(entry.name, advisory);
                    addAdvisoryToList(advisoriesByAuditKey, entry.auditKey, advisory);
                    for (const nodePath of entry.nodePaths) {
                        addAdvisoryToList(advisoriesByNodePath, nodePath, advisory);
                    }
                }
            }
        }
    }
    map.forEach((entry, name) => {
        map.set(name, summarizeAdvisories(entry.advisories || []));
    });
    const byNodePath = new Map();
    for (const [nodePath, advisories] of advisoriesByNodePath) {
        byNodePath.set(nodePath, summarizeAdvisories(advisories));
    }
    const byPackageId = new Map();
    for (const [packageId, advisories] of advisoriesByPackageId) {
        byPackageId.set(packageId, summarizeAdvisories(advisories));
    }
    return {
        byName: map,
        byNodePath,
        byPackageId,
        namesWithNodePaths: new Set(nodePathsByName.keys()),
        namesWithPackageIds: new Set(Array.from(advisoriesByPackageId.keys()).map((id) => id.slice(0, id.lastIndexOf('@')))),
    };
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
    else if ((declaredValidation === null || declaredValidation === void 0 ? void 0 : declaredValidation.valid) && inferred && inferred.confidence !== 'low') {
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
    if (scope === 'dev')
        return 'tooling';
    if (scope === 'peer' && runtimeImpact !== 'runtime')
        return 'tooling';
    if (rootNames.length > 0 && rootNames.every((root) => isToolingPackage(root)))
        return 'tooling';
    if (rootNames.some((root) => isFrameworkPackage(root)))
        return 'framework';
    if (rootNames.length > 0)
        return 'transitive';
    return 'unknown';
}
function isPermissiveNodeEngineRange(range) {
    const compact = range.trim().toLowerCase().replace(/\s+/g, '');
    return compact === '*' || compact === 'x' || compact === '>=0' || compact === '>=0.0' || compact === '>=0.0.0';
}
function hasNodeEngineUpgradeBlocker(nodeEngine) {
    if (!nodeEngine || !nodeEngine.trim())
        return false;
    if (isPermissiveNodeEngineRange(nodeEngine))
        return false;
    const clauses = nodeEngine.split('||').map((clause) => clause.trim()).filter(Boolean);
    if (clauses.length > 0 && clauses.every((clause) => isPermissiveNodeEngineRange(clause))) {
        return false;
    }
    const minMajor = parseMinMajorFromRange(nodeEngine);
    if (minMajor !== undefined) {
        if (minMajor > 0)
            return true;
        return /<\s*\d/.test(nodeEngine);
    }
    if (/<\s*\d/.test(nodeEngine))
        return true;
    const majors = Array.from(nodeEngine.matchAll(/v?(\d+)/g))
        .map((match) => Number.parseInt(match[1], 10))
        .filter((major) => Number.isFinite(major));
    return majors.some((major) => major > 0);
}
function hasInstallScriptUpgradeBlocker(execution) {
    var _a;
    const hooks = (_a = execution === null || execution === void 0 ? void 0 : execution.scripts) === null || _a === void 0 ? void 0 : _a.hooks;
    if (!hooks || hooks.length === 0)
        return false;
    return hooks.includes('preinstall') || hooks.includes('install') || hooks.includes('postinstall');
}
function buildUpgradeBlock(insights) {
    var _a;
    const blockers = [];
    const hasNodeEngineBlocker = hasNodeEngineUpgradeBlocker(insights.nodeEngine);
    const hasNativeBindingsBlocker = Boolean((_a = insights.execution) === null || _a === void 0 ? void 0 : _a.native);
    const hasInstallScriptBlocker = hasInstallScriptUpgradeBlocker(insights.execution);
    if (hasNodeEngineBlocker)
        blockers.push('nodeEngine');
    if (insights.requiredPeerDependencies > 0)
        blockers.push('peerDependency');
    if (hasNativeBindingsBlocker)
        blockers.push('nativeBindings');
    if (hasInstallScriptBlocker)
        blockers.push('installScripts');
    if (insights.deprecated)
        blockers.push('deprecated');
    if (blockers.length === 0)
        return undefined;
    const blocksNodeMajor = hasNodeEngineBlocker || hasNativeBindingsBlocker || hasInstallScriptBlocker;
    return {
        blockers,
        ...(blocksNodeMajor ? { blocksNodeMajor: true } : {})
    };
}
/**
 * Collects package metadata and bounded filesystem heuristics to produce insights used for dependency analysis.
 *
 * Gathers package.json data (description, engines, scripts, bin, dependencies, links), computes file-based stats when the package directory is available, detects TypeScript typing availability (bundled or DefinitelyTyped), counts required peer dependencies, and derives execution and packaging signals for use in aggregation and risk heuristics.
 *
 * @param resolvePaths - Array of filesystem roots to use when resolving package metadata.
 * @param metaCache - Cache mapping package id (`name` or `name@version`) to previously loaded PackageMeta to avoid repeated resolution and parsing.
 * @param statCache - Cache mapping package directory paths to previously computed PackageStats to avoid repeated filesystem scans.
 * @returns A PackageInsights object containing deprecation, engine constraint, required peer count, optional fileCount, declared dependency maps, links, execution signals, optional packaging signals, and TypeScript types information.
 */
async function gatherPackageInsights(name, version, resolvePaths, metaCache, statCache) {
    var _a;
    const meta = await loadPackageMeta(name, resolvePaths, metaCache, version);
    if (!meta) {
        return {
            deprecated: false,
            nodeEngine: null,
            requiredPeerDependencies: 0,
            hasBin: false,
            declaredDependencies: { dep: {}, dev: {}, peer: {}, opt: {} },
            tsTypes: 'unknown'
        };
    }
    const pkg = (meta === null || meta === void 0 ? void 0 : meta.pkg) || {};
    const dir = meta === null || meta === void 0 ? void 0 : meta.dir;
    const stats = dir ? await calculatePackageStats(dir, statCache) : undefined;
    const peerDependencies = normalizeDeclaredDeps(pkg.peerDependencies);
    const declaredDependencies = {
        dep: normalizeDeclaredDeps(pkg.dependencies),
        dev: normalizeDeclaredDeps(pkg.devDependencies),
        peer: peerDependencies,
        opt: normalizeDeclaredDeps(pkg.optionalDependencies)
    };
    const requiredPeerDependencies = countRequiredPeerDependencies(peerDependencies, pkg.peerDependenciesMeta);
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
    const execution = await deriveExecutionInfo(pkg, scripts, dir, stats);
    const packaging = derivePackagingInfo(pkg, stats);
    return {
        deprecated,
        nodeEngine,
        requiredPeerDependencies,
        description,
        ...(typeof (stats === null || stats === void 0 ? void 0 : stats.fileCount) === 'number' ? { fileCount: stats.fileCount } : {}),
        hasBin,
        declaredDependencies,
        links,
        execution,
        ...(packaging ? { packaging } : {}),
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
function countRequiredPeerDependencies(peerDependencies, peerDependenciesMeta) {
    if (!peerDependencies || Object.keys(peerDependencies).length === 0)
        return 0;
    const meta = peerDependenciesMeta && typeof peerDependenciesMeta === 'object'
        ? peerDependenciesMeta
        : {};
    let count = 0;
    for (const peerName of Object.keys(peerDependencies)) {
        const peerMeta = meta[peerName];
        const optional = Boolean(peerMeta &&
            typeof peerMeta === 'object' &&
            peerMeta.optional === true);
        if (!optional)
            count += 1;
    }
    return count;
}
/**
 * Detects whether a package.json `bin` field indicates at least one executable target.
 *
 * @param binField - The `bin` value from a package.json (string or object)
 * @returns `true` if `binField` contains at least one non-empty string entry, `false` otherwise.
 */
function hasPackageBin(binField) {
    if (typeof binField === 'string')
        return binField.trim().length > 0;
    if (!binField || typeof binField !== 'object')
        return false;
    return Object.values(binField).some((value) => typeof value === 'string' && value.trim().length > 0);
}
/**
 * Normalize a package's `bundledDependencies` / `bundleDependencies` field into a canonical list.
 *
 * @param pkg - The package.json-like object to read bundling metadata from
 * @returns A sorted list of bundled package names. Returns `['*']` when bundling is declared as `true`, or an empty array when no bundled dependencies are specified.
 */
function normalizeBundledDependencies(pkg) {
    if ((pkg === null || pkg === void 0 ? void 0 : pkg.bundledDependencies) === true || (pkg === null || pkg === void 0 ? void 0 : pkg.bundleDependencies) === true) {
        return ['*'];
    }
    const raw = Array.isArray(pkg === null || pkg === void 0 ? void 0 : pkg.bundledDependencies)
        ? pkg.bundledDependencies
        : Array.isArray(pkg === null || pkg === void 0 ? void 0 : pkg.bundleDependencies)
            ? pkg.bundleDependencies
            : [];
    const entries = raw
        .map((entry) => typeof entry === 'string' ? entry.trim() : '')
        .filter((entry) => entry.length > 0);
    return Array.from(new Set(entries)).sort();
}
/**
 * Derives packaging-related signals from a package manifest and optional filesystem stats.
 *
 * @param pkg - The package.json object for the package being analyzed.
 * @param stats - Optional file-statistics for the package directory (e.g., presence of shrinkwrap).
 * @returns Packaging information containing `signals` (one or more of `bundled-dependencies` and `embedded-shrinkwrap`) and, when present, a `bundledDependencies` list; returns `undefined` when no packaging signals are detected.
 */
function derivePackagingInfo(pkg, stats) {
    const signals = new Set();
    const bundledDependencies = normalizeBundledDependencies(pkg);
    if (bundledDependencies.length > 0)
        signals.add('bundled-dependencies');
    if (stats === null || stats === void 0 ? void 0 : stats.hasShrinkwrap)
        signals.add('embedded-shrinkwrap');
    const signalList = ['bundled-dependencies', 'embedded-shrinkwrap']
        .filter((signal) => signals.has(signal));
    if (signalList.length === 0)
        return undefined;
    return {
        signals: signalList,
        ...(bundledDependencies.length > 0 ? { bundledDependencies } : {})
    };
}
/**
 * Load and cache a package's package.json and its directory metadata.
 *
 * @param name - Package name to resolve
 * @param resolvePaths - Ordered list of base paths to use when resolving the package.json
 * @param cache - Map used to store and reuse previously loaded PackageMeta entries; keyed by `name` or `name@version`
 * @param version - Optional version hint used when resolving a specific package variant
 * @returns The `PackageMeta` containing the parsed `package.json` (`pkg`) and its directory (`dir`), or `undefined` if the package.json could not be resolved or read
 */
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
/**
 * Collects filesystem-derived statistics for a package directory.
 *
 * Scans the package directory (best-effort) to detect whether the package
 * contains TypeScript declaration files, native binary artifacts, a
 * binding.gyp file, or an npm shrinkwrap file, and counts files. Nested
 * dependency stores (node_modules) and .git directories are ignored; I/O
 * errors are swallowed and the function returns whatever information could
 * be gathered.
 *
 * @param dir - Filesystem path to the package directory to inspect.
 * @param cache - Memoization map keyed by directory path; cached results are
 *                returned when available and new results are stored here.
 * @returns An object with:
 *          - `hasDts`: `true` when any `.d.ts` files were found.
 *          - `hasNativeBinary`: `true` when any `.node` binaries were found.
 *          - `hasBindingGyp`: `true` when a `binding.gyp` file was found.
 *          - `hasShrinkwrap`: `true` when an `npm-shrinkwrap.json` file was found.
 *          - `fileCount`: total number of regular files encountered under the directory.
 */
async function calculatePackageStats(dir, cache) {
    if (cache.has(dir))
        return cache.get(dir);
    let hasDts = false;
    let hasNativeBinary = false;
    let hasBindingGyp = false;
    let hasShrinkwrap = false;
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
                if (entry.name === 'npm-shrinkwrap.json')
                    hasShrinkwrap = true;
            }
        }
    }
    try {
        await walk(dir);
    }
    catch (err) {
        // best-effort; ignore inaccessible paths
    }
    const result = { hasDts, hasNativeBinary, hasBindingGyp, hasShrinkwrap, fileCount };
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
    try {
        const parsed = new URL(cleaned + hash);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
            return undefined;
        parsed.username = '';
        parsed.password = '';
        return parsed.toString();
    }
    catch {
        return undefined;
    }
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
const LOCAL_SIGNAL_MAX_FILES_PER_PACKAGE = 24;
const LOCAL_SIGNAL_MAX_BYTES_PER_FILE = 120000;
const LOCAL_SIGNAL_MAX_PACKAGE_FILES = 2000;
const COMPLEXITY_THRESHOLD = 12;
/**
 * Collects non-empty lifecycle hook commands from a package `scripts` object.
 *
 * @param scripts - The `scripts` section from a package.json (map of script names to values).
 * @returns An object mapping each lifecycle hook found in `scripts` to its trimmed command; only hooks defined in `LIFECYCLE_HOOKS` and with non-empty string values are included.
 */
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
/**
 * Finds the first Node script file path referenced by lifecycle hook commands, checking hooks in predefined order.
 *
 * @param lifecycleScripts - Map of lifecycle hook names to their command strings; only hooks with non-empty commands are inspected.
 * @returns The referenced script path (as found in a `node <script>` invocation) when present, `undefined` otherwise.
 */
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
/**
 * Normalize an input into a package-relative path by trimming whitespace and removing a leading `./` or `.\`.
 *
 * @param value - The input value to normalize (expected to be a path string)
 * @returns The cleaned package-relative path, or `undefined` if the input is not a string, is empty after trimming, or appears to be an absolute/URL (contains `://`)
 */
function normalizePackageRelativePath(value) {
    if (typeof value !== 'string')
        return undefined;
    const cleaned = value.trim().replace(/^[.][/\\]/, '');
    if (!cleaned || cleaned.includes('://'))
        return undefined;
    return cleaned;
}
/**
 * Collects normalized executable entry targets from a package `bin` field.
 *
 * @param binField - The package `bin` field; may be a string or an object mapping executable names to paths.
 * @returns An array of normalized package-relative executable target paths, deduplicated and sorted.
 */
function packageBinTargets(binField) {
    const targets = new Set();
    const add = (value) => {
        const normalized = normalizePackageRelativePath(value);
        if (normalized)
            targets.add(normalized);
    };
    if (typeof binField === 'string')
        add(binField);
    else if (binField && typeof binField === 'object') {
        for (const value of Object.values(binField))
            add(value);
    }
    return Array.from(targets).sort();
}
/**
 * Collects candidate entry file paths from a package manifest.
 *
 * Supports `main`, `module`, and `exports` fields, flattening arrays and objects and normalizing package-relative paths.
 *
 * @param pkg - The package.json object to read entry targets from
 * @returns An array of normalized package-relative entry paths, sorted; contains `index.js` when no entry fields are present
 */
function packageEntryTargets(pkg) {
    const targets = new Set();
    const add = (value) => {
        if (typeof value === 'string') {
            const normalized = normalizePackageRelativePath(value);
            if (normalized)
                targets.add(normalized);
            return;
        }
        if (Array.isArray(value)) {
            value.forEach(add);
            return;
        }
        if (value && typeof value === 'object') {
            Object.values(value).forEach(add);
        }
    };
    add(pkg === null || pkg === void 0 ? void 0 : pkg.main);
    add(pkg === null || pkg === void 0 ? void 0 : pkg.module);
    add(pkg === null || pkg === void 0 ? void 0 : pkg.exports);
    if (targets.size === 0)
        targets.add('index.js');
    return Array.from(targets).sort();
}
/**
 * Reads an install script file from a package directory if it is a regular file within size limits.
 *
 * @param scriptPath - The path to the script file as referenced in package scripts (resolved relative to `packageDir`)
 * @param packageDir - The package root directory used to resolve and bound `scriptPath`
 * @returns The file contents as UTF-8 text when the file exists inside `packageDir`, is a regular file, and its size is at most `INSTALL_SCRIPT_MAX_BYTES`; `undefined` otherwise.
 */
async function readInstallScriptFile(scriptPath, packageDir) {
    const resolvedDir = path_1.default.resolve(packageDir);
    const resolvedPath = path_1.default.resolve(resolvedDir, scriptPath);
    if (!resolvedPath.startsWith(resolvedDir + path_1.default.sep))
        return undefined;
    // Stat and read through one handle so the checked file and the read file
    // cannot differ (avoids a check-then-use race on the path).
    let handle;
    try {
        handle = await promises_1.default.open(resolvedPath, 'r');
        const stat = await handle.stat();
        if (!stat.isFile())
            return undefined;
        return await readHandleCapped(handle, INSTALL_SCRIPT_MAX_BYTES);
    }
    catch {
        return undefined;
    }
    finally {
        await (handle === null || handle === void 0 ? void 0 : handle.close().catch(() => undefined));
    }
}
/**
 * Read at most `maxBytes` from an open handle, enforcing the cap during the
 * read itself so a file that grows after being stat'ed cannot exceed it.
 *
 * @returns The UTF-8 content, or `undefined` when the file exceeds `maxBytes`.
 */
async function readHandleCapped(handle, maxBytes) {
    const cap = maxBytes + 1;
    const buffer = Buffer.alloc(cap);
    let offset = 0;
    while (offset < cap) {
        const { bytesRead } = await handle.read(buffer, offset, cap - offset, offset);
        if (bytesRead === 0)
            break;
        offset += bytesRead;
    }
    if (offset > maxBytes)
        return undefined;
    return buffer.subarray(0, offset).toString('utf8');
}
/**
 * Checks whether a file path refers to an inspectable source file used for static analysis.
 *
 * @param filePath - The file path to test (relative or absolute)
 * @returns `true` if the path ends with a JS/TS-related extension (`.js`, `.cjs`, `.mjs`, `.jsx`, `.ts`, `.tsx`) or has no extension, `false` otherwise.
 */
function isInspectableSourcePath(filePath) {
    return /\.(?:js|cjs|mjs|jsx|ts|tsx)$/i.test(filePath) || path_1.default.extname(filePath) === '';
}
/**
 * Detects whether a JavaScript-like file is likely minified or otherwise obfuscated.
 *
 * Uses filename and simple content heuristics to identify minified files.
 *
 * @param fileName - The file name or path (used to detect `.min.js/.min.cjs/.min.mjs` suffixes)
 * @param text - The file contents to inspect
 * @returns `true` if the file appears minified or obfuscated, `false` otherwise.
 */
function looksMinified(fileName, text) {
    if (/\.min\.(?:js|cjs|mjs)$/i.test(fileName))
        return true;
    const lines = text.split(/\r?\n/);
    if (lines.length <= 3 && text.length > 20000)
        return true;
    return lines.some((line) => line.length > 10000);
}
/**
 * Determine whether a string appears to be readable text (not binary or overwhelmingly control-character data).
 *
 * Empty strings are considered text; presence of a NUL character marks the input as non-text. The function treats
 * the input as text when the proportion of suspicious control or replacement characters is less than 1%.
 *
 * @param text - The string to evaluate
 * @returns `true` if the input appears to be readable text, `false` otherwise.
 */
function looksTextLike(text) {
    if (text.includes('\0'))
        return false;
    if (text.length === 0)
        return true;
    const suspicious = (text.match(/[\uFFFD\x00-\x08\x0E-\x1F]/g) || []).length;
    return suspicious / text.length < 0.01;
}
/**
 * Detects whether a text blob appears to be JavaScript or Node.js source.
 *
 * @param text - The text to inspect for JavaScript/Node indicators
 * @returns `true` if the text contains common JavaScript or Node.js source markers (shebang with `node`, `require(`, `import`, `module.exports`, or `process.`), `false` otherwise
 */
function looksJavaScriptLike(text) {
    return (/^#!.*\bnode\b/.test(text) ||
        /\brequire\s*\(/.test(text) ||
        /\bimport\s+/.test(text) ||
        /\bmodule\.exports\b/.test(text) ||
        /\bprocess\./.test(text));
}
/**
 * Read and return the text of a package-relative source file when it is safe and useful to inspect.
 *
 * Attempts to resolve and read `filePath` inside `packageDir` and returns the file contents only if the file:
 * - resides within `packageDir`,
 * - matches the allowed inspectable source path patterns,
 * - is a regular file whose size does not exceed `maxBytes`,
 * - appears to be text (and, for extensionless files, looks like JavaScript),
 * - does not appear minified or otherwise obfuscated.
 *
 * @param filePath - Path to the candidate file relative to the package directory
 * @param packageDir - Absolute path of the package root to constrain reads
 * @param maxBytes - Maximum number of bytes to read from the file (per-file size limit)
 * @returns The file content when it is inspectable under the above constraints, `undefined` otherwise
 */
async function readInspectablePackageFile(filePath, packageDir, maxBytes = LOCAL_SIGNAL_MAX_BYTES_PER_FILE) {
    const resolvedDir = path_1.default.resolve(packageDir);
    const resolvedPath = path_1.default.resolve(resolvedDir, filePath);
    if (!resolvedPath.startsWith(resolvedDir + path_1.default.sep))
        return undefined;
    if (!isInspectableSourcePath(resolvedPath))
        return undefined;
    // Stat and read through one handle so the checked file and the read file
    // cannot differ (avoids a check-then-use race on the path).
    let handle;
    try {
        handle = await promises_1.default.open(resolvedPath, 'r');
        const stat = await handle.stat();
        if (!stat.isFile())
            return undefined;
        const text = await readHandleCapped(handle, maxBytes);
        if (text === undefined)
            return undefined;
        if (!looksTextLike(text))
            return undefined;
        if (path_1.default.extname(resolvedPath) === '' && !looksJavaScriptLike(text))
            return undefined;
        if (looksMinified(resolvedPath, text))
            return undefined;
        return text;
    }
    catch {
        return undefined;
    }
    finally {
        await (handle === null || handle === void 0 ? void 0 : handle.close().catch(() => undefined));
    }
}
/**
 * Collects a bounded list of inspectable source file paths inside a package directory.
 *
 * Traverses the package tree (skipping symlinks and common non-source directories) and returns
 * a sorted array of package-relative paths for files considered inspectable.
 *
 * @param packageDir - Absolute path to the package directory to scan
 * @param maxFiles - Maximum number of inspectable file paths to return
 * @param maxPackageFiles - Maximum number of files to examine within the package (counts all files visited)
 * @returns A sorted array of relative file paths (relative to `packageDir`) for inspectable source files
 */
async function collectBoundedInspectableFiles(packageDir, maxFiles, maxPackageFiles) {
    const out = [];
    let seen = 0;
    async function walk(current) {
        if (out.length >= maxFiles || seen >= maxPackageFiles)
            return;
        const entries = await promises_1.default.readdir(current, { withFileTypes: true }).catch(() => []);
        entries.sort((a, b) => a.name.localeCompare(b.name, 'en', { numeric: true, sensitivity: 'base' }));
        for (const entry of entries) {
            if (out.length >= maxFiles || seen >= maxPackageFiles)
                return;
            const full = path_1.default.join(current, entry.name);
            if (entry.isSymbolicLink())
                continue;
            if (entry.isDirectory()) {
                if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'test' || entry.name === 'tests' || entry.name === 'docs')
                    continue;
                await walk(full);
            }
            else if (entry.isFile()) {
                seen += 1;
                if (isInspectableSourcePath(full)) {
                    out.push(path_1.default.relative(packageDir, full));
                }
            }
        }
    }
    await walk(packageDir);
    return out.sort();
}
/**
 * Identify execution-related static signals present in a block of source or script text.
 *
 * @param text - The file or lifecycle script text to analyze for execution signals
 * @returns An ordered array of distinct execution signals detected in `text`, prioritized according to the canonical execution-signal ordering
 */
function detectLocalExecutionSignals(text) {
    const signals = new Set();
    detectFileSignals(text, signals);
    return EXECUTION_SIGNAL_ORDER.filter((signal) => signals.has(signal));
}
/**
 * Checks whether the given text matches any regular expression in the provided list.
 *
 * @param text - The string to test against the patterns
 * @param patterns - Array of `RegExp` objects to test
 * @returns `true` if at least one pattern matches `text`, `false` otherwise.
 */
function textHasAny(text, patterns) {
    return patterns.some((pattern) => pattern.test(text));
}
/**
 * Detects install-time script characteristics from a text blob and adds matching execution signals to the provided set.
 *
 * Examines the input text with heuristics for common patterns and adds any of the following `ExecutionSignal` values to `signals` when matched:
 * - `network-access` — patterns that fetch remote resources (curl, wget, http(s), fetch, axios, net.connect, dns, etc.).
 * - `reads-env` — access to environment variables or printenv-style usage.
 * - `reads-home` — references to user home paths or APIs returning the home directory.
 * - `uses-ssh` — references to SSH-related files, agents, or SSH/git configuration.
 *
 * @param text - The script or file text to statically inspect for indicative patterns.
 * @param signals - A mutable Set that will receive any detected execution signals.
 */
function detectScriptSignals(text, signals) {
    // Signals are derived from static text inspection only: no code execution and no import walking.
    // They are NOT malware detection; they merely highlight review-worthy install-time behavior.
    // "network-access" surfaces install scripts that fetch remote resources (review for expected downloads; does NOT imply exfiltration).
    if (textHasAny(text, [/\bcurl\b/i, /\bwget\b/i, /https?:\/\//i, /\bfetch\s*\(/i, /\baxios\b/i, /node-fetch/i, /\bhttps?\.request\s*\(/, /\bnet\.connect\s*\(/, /\bdns\./])) {
        signals.add('network-access');
    }
    // "reads-env" highlights environment access (does NOT imply exfiltration).
    if (textHasAny(text, [/\bprocess\.env\b/, /\bprintenv\b/i, /\benv\s*\|/i])) {
        signals.add('reads-env');
    }
    // "reads-home" highlights access to user home paths (does NOT imply credential theft).
    if (textHasAny(text, [/\$HOME\b/, /process\.env\.HOME\b/, /\bUSERPROFILE\b/, /os\.homedir\s*\(/, /~\//, /\/Users\//, /\/home\//])) {
        signals.add('reads-home');
    }
    // "uses-ssh" flags access to SSH-related paths (does NOT imply key exfiltration).
    if (textHasAny(text, [/\.ssh\b/i, /id_rsa\b/i, /known_hosts\b/i, /ssh-key/i, /ssh-agent/i, /GIT_SSH_COMMAND\b/, /\.npmrc\b/i])) {
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
/**
 * Detects static execution- and obfuscation-related signals from a JavaScript file's text and adds them to `signals`.
 *
 * Scans the provided source text for review cues such as script-level indicators, dynamic code execution APIs, child-process usage, explicit encoding patterns, and signs of obfuscation/minification. Matches are added to the supplied `signals` set; the function does not return a value and does not imply malicious intent by itself.
 *
 * @param text - The source text of a JavaScript file to analyze.
 * @param signals - A mutable set that will be populated with discovered `ExecutionSignal` values.
 */
function detectFileSignals(text, signals) {
    // Signals from a single directly-referenced JS file (no execution, no imports, no deep scanning).
    // These are review cues only and do NOT imply malicious intent.
    detectScriptSignals(text, signals);
    // "dynamic-exec" flags dynamic code execution APIs (does NOT imply malicious behavior).
    if (textHasAny(text, [/\beval\s*\(/, /new\s+Function\s*\(/, /\bvm\.runIn/i])) {
        signals.add('dynamic-exec');
    }
    // "child-process" flags process spawning (does NOT imply abuse).
    if (textHasAny(text, [/\bchild_process\b/, /\bexec\s*\(/, /\bspawn\s*\(/, /\bexecFile\s*\(/, /\bexecSync\s*\(/, /\bspawnSync\s*\(/])) {
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
/**
 * Classifies execution-related risk level for a package based on lifecycle scripts, detected signals, and script complexity.
 *
 * @param hasScripts - Whether the package defines any lifecycle scripts
 * @param hasSignals - Whether static analysis detected execution-related signals (network, child-process, dynamic execution, etc.)
 * @param highComplexity - Whether the package's lifecycle scripts exceed the complexity threshold
 * @param hooks - Lifecycle hooks present (note: `install` or `postinstall` count as install-time hooks)
 * @returns `'red'` when scripts are present and either execution signals exist or scripts are highly complex on an install-time hook; `'amber'` otherwise.
 */
function determineExecutionRisk(hasScripts, hasSignals, highComplexity, hooks) {
    const hasInstallHook = hooks.includes('install') || hooks.includes('postinstall');
    if (hasScripts && (hasSignals || (highComplexity && hasInstallHook)))
        return 'red';
    return 'amber';
}
/**
 * Collects execution-related static signals from a package's likely entry and inspectable source files using bounded, best-effort inspection.
 *
 * This inspects candidate entry points (e.g., `bin`, `main`, `module`, `exports`) plus a bounded set of other inspectable files, applies static detectors, and returns the detected execution signals in the canonical ordering.
 *
 * @param pkg - The package.json object for the package being inspected.
 * @param packageDir - The package filesystem directory to read files from; when `undefined`, the function returns an empty array.
 * @param options.maxFiles - Maximum number of files to inspect (default: LOCAL_SIGNAL_MAX_FILES_PER_PACKAGE).
 * @param options.maxBytesPerFile - Maximum bytes to read per file (default: LOCAL_SIGNAL_MAX_BYTES_PER_FILE).
 * @param options.maxPackageFiles - Maximum number of candidate package files to enumerate before selecting up to `maxFiles` for inspection (default: LOCAL_SIGNAL_MAX_PACKAGE_FILES).
 * @returns An array of detected `ExecutionSignal` values, ordered according to the canonical `EXECUTION_SIGNAL_ORDER`. Empty if no signals are found.
 */
async function collectPackageExecutionSignals(pkg, packageDir, options = {}) {
    var _a, _b, _c;
    if (!packageDir)
        return [];
    const maxFiles = (_a = options.maxFiles) !== null && _a !== void 0 ? _a : LOCAL_SIGNAL_MAX_FILES_PER_PACKAGE;
    const maxBytesPerFile = (_b = options.maxBytesPerFile) !== null && _b !== void 0 ? _b : LOCAL_SIGNAL_MAX_BYTES_PER_FILE;
    const maxPackageFiles = (_c = options.maxPackageFiles) !== null && _c !== void 0 ? _c : LOCAL_SIGNAL_MAX_PACKAGE_FILES;
    const candidateFiles = new Set();
    for (const file of [...packageBinTargets(pkg === null || pkg === void 0 ? void 0 : pkg.bin), ...packageEntryTargets(pkg)]) {
        candidateFiles.add(file);
    }
    for (const file of await collectBoundedInspectableFiles(packageDir, maxFiles, maxPackageFiles)) {
        candidateFiles.add(file);
        if (candidateFiles.size >= maxFiles)
            break;
    }
    const signals = new Set();
    let inspected = 0;
    for (const file of candidateFiles) {
        if (inspected >= maxFiles)
            break;
        const text = await readInspectablePackageFile(file, packageDir, maxBytesPerFile);
        if (!text)
            continue;
        inspected += 1;
        detectFileSignals(text, signals);
    }
    return EXECUTION_SIGNAL_ORDER.filter((signal) => signals.has(signal));
}
/**
 * Derives install-time execution signals, script metadata, and a consolidated execution risk for a package.
 *
 * Analyzes lifecycle hooks, referenced install scripts, native-build indicators, and bounded package file inspection to produce ordered execution signals, an execution complexity score when applicable, and a risk classification. Returns undefined when no meaningful execution signals, scripts, or native indicators are present.
 *
 * @param pkg - The package.json object for the dependency; used to locate entry points and candidate files for inspection.
 * @param scripts - The package's lifecycle `scripts` map (from package.json).
 * @param packageDir - Absolute path to the package directory used for reading referenced install scripts and package files; when undefined, file-based inspection is skipped.
 * @param stats - Optional PackageStats containing file-based heuristics (e.g., `hasNativeBinary`, `hasBindingGyp`) used as native indicators.
 * @returns An execution record containing:
 *  - `risk`: computed execution risk,
 *  - optional `native`: `true` when native-build indicators are present,
 *  - optional `signals`: ordered list of detected execution signals,
 *  - optional `scripts`: metadata about lifecycle hooks including `hooks`, optional `complexity`, and optional script-only `signals`.
 */
async function deriveExecutionInfo(pkg, scripts, packageDir, stats) {
    const lifecycleScripts = collectLifecycleScripts(scripts);
    const hooks = LIFECYCLE_HOOKS.filter((hook) => Boolean(lifecycleScripts[hook]));
    const hasScripts = hooks.length > 0;
    const hasNative = Boolean((stats === null || stats === void 0 ? void 0 : stats.hasNativeBinary) || (stats === null || stats === void 0 ? void 0 : stats.hasBindingGyp) || scriptsContainNativeTooling(scripts));
    const scriptSignals = new Set();
    const combinedScripts = hooks.map((hook) => lifecycleScripts[hook]).join('\n');
    if (combinedScripts) {
        detectScriptSignals(combinedScripts, scriptSignals);
    }
    if (hasScripts && packageDir) {
        const referencedScript = findReferencedInstallScript(lifecycleScripts);
        if (referencedScript) {
            const fileContent = await readInstallScriptFile(referencedScript, packageDir);
            if (fileContent) {
                detectFileSignals(fileContent, scriptSignals);
            }
        }
    }
    const packageSignals = await collectPackageExecutionSignals(pkg, packageDir);
    const allSignals = new Set([...scriptSignals, ...packageSignals]);
    const complexityScore = hasScripts ? scoreLifecycleScripts(lifecycleScripts) : 0;
    const complexity = complexityScore >= COMPLEXITY_THRESHOLD ? complexityScore : undefined;
    const scriptSignalList = EXECUTION_SIGNAL_ORDER.filter((signal) => scriptSignals.has(signal));
    const signalList = EXECUTION_SIGNAL_ORDER.filter((signal) => allSignals.has(signal));
    if (!hasScripts && !hasNative && signalList.length === 0)
        return undefined;
    const scriptsInfo = {
        hooks,
        ...(complexity !== undefined ? { complexity } : {}),
        ...(scriptSignalList.length > 0 ? { signals: scriptSignalList } : {})
    };
    const risk = determineExecutionRisk(hasScripts, signalList.length > 0, complexity !== undefined, hooks);
    const execution = { risk };
    // Native is surface description only; not a behavioral signal.
    if (hasNative)
        execution.native = true;
    if (signalList.length > 0)
        execution.signals = signalList;
    if (hasScripts)
        execution.scripts = scriptsInfo;
    return execution;
}
