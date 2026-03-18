"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.findDependenciesByPackageName = findDependenciesByPackageName;
exports.formatExplainOutput = formatExplainOutput;
const BLOCKER_LABELS = {
    nodeEngine: 'Node engine constraint',
    peerDependency: 'Peer dependency constraints',
    nativeBindings: 'Native bindings/build tooling',
    installScripts: 'Install lifecycle scripts',
    deprecated: 'Deprecated by author',
};
function findDependenciesByPackageName(aggregated, packageName) {
    return Object.values(aggregated.dependencies || {})
        .filter((dep) => dep.package.name === packageName)
        .sort((a, b) => {
        if (a.usage.direct !== b.usage.direct) {
            return a.usage.direct ? -1 : 1;
        }
        return compareVersionStrings(b.package.version, a.package.version);
    });
}
function formatExplainOutput(packageName, matches, context) {
    var _a, _b, _c, _d;
    if (matches.length === 0) {
        return `✖ Package not found: ${packageName}`;
    }
    const versions = Array.from(new Set(matches.map((dep) => dep.package.version))).sort((a, b) => compareVersionStrings(b, a));
    const lines = [];
    const header = versions.length > 1
        ? `${packageName} (${versions.length} versions detected)`
        : packageName;
    lines.push(header);
    lines.push('-'.repeat(Math.max(header.length, 24)));
    lines.push('');
    for (let index = 0; index < matches.length; index += 1) {
        const dep = matches[index];
        const staticImportEvidence = resolveStaticImportEvidence(dep, context);
        const vulnerabilitySummary = formatVulnerabilitySummary(dep, context.audit);
        const licenseSummary = formatLicenseSummary(dep);
        const otherVersions = versions.filter((version) => version !== dep.package.version);
        lines.push(dep.package.id);
        lines.push('');
        lines.push(`Type: ${dep.usage.direct ? 'direct' : 'transitive'}`);
        lines.push(`Scope: ${dep.usage.scope}`);
        lines.push(`Introduction: ${dep.usage.introduction || 'unknown'}`);
        lines.push(`Runtime impact: ${dep.usage.runtimeImpact || 'not detected'}`);
        lines.push(`Static import evidence: ${staticImportEvidence}`);
        lines.push('');
        pushListSection(lines, 'Introduced via root packages', [
            ...dep.usage.origins.topRootPackages.map((root) => `${root.name}@${root.version}`),
            ...formatOverflowLine(dep.usage.origins.rootPackageCount -
                dep.usage.origins.topRootPackages.length, 'root packages'),
        ], dep.usage.direct ? 'top-level dependency' : 'none identified');
        pushListSection(lines, 'Direct parents', [
            ...dep.usage.origins.topParentPackages,
            ...formatOverflowLine(dep.usage.origins.parentPackageCount -
                dep.usage.origins.topParentPackages.length, 'parents'),
        ], dep.usage.direct ? 'top-level dependency' : 'none identified');
        if ((_a = dep.usage.origins.workspaces) === null || _a === void 0 ? void 0 : _a.length) {
            pushListSection(lines, 'Workspaces', dep.usage.origins.workspaces, 'none');
        }
        if ((_c = (_b = dep.usage.importUsage) === null || _b === void 0 ? void 0 : _b.topFiles) === null || _c === void 0 ? void 0 : _c.length) {
            pushListSection(lines, 'Imported in', [
                ...dep.usage.importUsage.topFiles,
                ...formatOverflowLine(dep.usage.importUsage.fileCount - dep.usage.importUsage.topFiles.length, 'files'),
            ]);
        }
        else if (context.importGraphComplete) {
            lines.push('Imported in:');
            lines.push('  No static import references found');
        }
        else {
            lines.push('Imported in:');
            lines.push('  unavailable (import graph incomplete)');
        }
        lines.push('');
        lines.push('Vulnerabilities:');
        lines.push(`  ${vulnerabilitySummary}`);
        lines.push('');
        lines.push('License:');
        lines.push(`  ${licenseSummary}`);
        lines.push('');
        lines.push('Upgrade blockers:');
        if ((_d = dep.upgrade.blockers) === null || _d === void 0 ? void 0 : _d.length) {
            for (const blocker of dep.upgrade.blockers) {
                lines.push(`  - ${BLOCKER_LABELS[blocker] || blocker}`);
            }
        }
        else {
            lines.push('  none');
        }
        if (otherVersions.length > 0) {
            lines.push('');
            lines.push('Other detected versions:');
            for (const version of otherVersions) {
                lines.push(`  ${version}`);
            }
        }
        if (index < matches.length - 1) {
            lines.push('');
            lines.push('');
        }
    }
    return lines.join('\n');
}
function pushListSection(lines, label, values, emptyFallback = 'none') {
    lines.push(`${label}:`);
    if (values.length === 0) {
        lines.push(`  ${emptyFallback}`);
    }
    else {
        for (const value of values) {
            lines.push(`  ${value}`);
        }
    }
    lines.push('');
}
function formatOverflowLine(count, noun) {
    if (count <= 0)
        return [];
    return [`+${count} more ${noun}`];
}
function resolveStaticImportEvidence(dep, context) {
    var _a;
    if ((_a = dep.usage.importUsage) === null || _a === void 0 ? void 0 : _a.fileCount)
        return 'yes';
    return context.importGraphComplete ? 'no' : 'unknown';
}
function formatVulnerabilitySummary(dep, availability) {
    if (availability === 'skipped') {
        return 'not available (--offline)';
    }
    if (availability === 'unavailable') {
        return 'not available (audit failed)';
    }
    const summary = dep.security.summary;
    const total = (summary.critical || 0) +
        (summary.high || 0) +
        (summary.moderate || 0) +
        (summary.low || 0);
    if (total === 0)
        return 'none';
    const advisoryLabel = total === 1 ? 'advisory' : 'advisories';
    return `${total} ${advisoryLabel} (highest severity: ${summary.highest})`;
}
function formatLicenseSummary(dep) {
    var _a, _b;
    const license = dep.compliance.license;
    const declared = (_a = license.declared) === null || _a === void 0 ? void 0 : _a.spdxId;
    const inferred = (_b = license.inferred) === null || _b === void 0 ? void 0 : _b.spdxId;
    switch (license.status) {
        case 'match':
            return `${declared || inferred || 'unknown'} (declared + inferred match)`;
        case 'declared-only':
            return `${declared || 'unknown'} (declared)`;
        case 'inferred-only':
            return `${inferred || 'unknown'} (inferred)`;
        case 'mismatch':
            return `mismatch (declared ${declared || 'unknown'}, inferred ${inferred || 'unknown'})`;
        case 'invalid-spdx':
            return `invalid SPDX (${declared || 'unknown'})`;
        default:
            return 'unknown';
    }
}
function compareVersionStrings(left, right) {
    const leftParts = tokenizeVersion(left);
    const rightParts = tokenizeVersion(right);
    const maxLength = Math.max(leftParts.length, rightParts.length);
    for (let index = 0; index < maxLength; index += 1) {
        const leftPart = leftParts[index];
        const rightPart = rightParts[index];
        if (leftPart === undefined)
            return -1;
        if (rightPart === undefined)
            return 1;
        if (typeof leftPart === 'number' && typeof rightPart === 'number') {
            if (leftPart !== rightPart)
                return leftPart - rightPart;
            continue;
        }
        const compared = String(leftPart).localeCompare(String(rightPart));
        if (compared !== 0)
            return compared;
    }
    return left.localeCompare(right);
}
function tokenizeVersion(value) {
    return value
        .split(/([0-9]+)/)
        .filter(Boolean)
        .map((part) => (/^[0-9]+$/.test(part) ? Number.parseInt(part, 10) : part));
}
