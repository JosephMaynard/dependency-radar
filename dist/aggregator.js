"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.aggregateData = aggregateData;
const utils_1 = require("./utils");
const MAINTENANCE_LOOKUP_LIMIT = 50;
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
    const nodeMap = buildNodeMap((_f = input.npmLsResult) === null || _f === void 0 ? void 0 : _f.data, pkg);
    const vulnMap = parseVulnerabilities((_g = input.auditResult) === null || _g === void 0 ? void 0 : _g.data);
    const licenseData = normalizeLicenseData((_h = input.licenseResult) === null || _h === void 0 ? void 0 : _h.data);
    const depcheckUsage = buildUsageInfo((_j = input.depcheckResult) === null || _j === void 0 ? void 0 : _j.data);
    const importInfo = buildImportInfo((_k = input.madgeResult) === null || _k === void 0 ? void 0 : _k.data);
    const maintenanceCache = new Map();
    let maintenanceLookups = 0;
    const dependencies = [];
    const licenseFallbackCache = new Map();
    for (const node of nodeMap.values()) {
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
        const allowLookup = maintenanceLookups < MAINTENANCE_LOOKUP_LIMIT;
        const maintenance = await resolveMaintenance(node.name, maintenanceCache, allowLookup);
        if (!maintenanceCache.has(node.name)) {
            maintenanceCache.set(node.name, maintenance);
            if (maintenance.status !== 'unknown' && allowLookup) {
                maintenanceLookups++;
            }
        }
        const maintenanceRiskLevel = (0, utils_1.maintenanceRisk)(maintenance.lastPublished);
        const runtimeData = classifyRuntime(node, pkg, nodeMap);
        dependencies.push({
            name: node.name,
            version: node.version,
            key: node.key,
            direct,
            transitive: !direct,
            depth: node.depth,
            parents: Array.from(node.parents),
            license,
            licenseRisk,
            vulnerabilities,
            vulnRisk,
            maintenance,
            maintenanceRisk: maintenanceRiskLevel,
            usage,
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
        }
        if (node.dependencies && typeof node.dependencies === 'object') {
            Object.entries(node.dependencies).forEach(([depName, child]) => traverse(child, depth + 1, key, depName));
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
            map.set(key, { name, version, key, depth: 1, parents: new Set(), dev: false });
        });
        devDeps.forEach((name) => {
            const version = pkg.devDependencies[name];
            const key = `${name}@${version}`;
            map.set(key, { name, version, key, depth: 1, parents: new Set(), dev: true });
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
async function resolveMaintenance(name, cache, allowLookup) {
    if (cache.has(name))
        return cache.get(name);
    if (!allowLookup) {
        return { status: 'unknown', reason: 'lookup cap reached' };
    }
    try {
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
        return { status: 'unknown', reason: `lookup failed: ${String(err)}` };
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
