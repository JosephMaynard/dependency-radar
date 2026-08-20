"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.reportVulnerabilityTotal = reportVulnerabilityTotal;
exports.reportAllExecutionSignals = reportAllExecutionSignals;
exports.buildReportOverallRisk = buildReportOverallRisk;
exports.buildReportKeyPoints = buildReportKeyPoints;
const supplyChainCombos_1 = require("./supplyChainCombos");
const EXECUTION_SIGNAL_LABELS = {
    'network-access': 'Accesses network during install',
    'dynamic-exec': 'Uses dynamic execution',
    'child-process': 'Spawns child processes',
    encoding: 'Uses encoding/decoding logic',
    obfuscated: 'Contains obfuscated/minified install logic',
    'reads-env': 'Reads environment variables',
    'reads-home': 'Reads user home directory',
    'uses-ssh': 'Uses SSH configuration/keys'
};
function reportVulnerabilityTotal(summary) {
    return summary.critical + summary.high + summary.moderate + summary.low;
}
function reportAllExecutionSignals(dep) {
    var _a, _b, _c;
    return Array.from(new Set([
        ...(((_b = (_a = dep.execution) === null || _a === void 0 ? void 0 : _a.scripts) === null || _b === void 0 ? void 0 : _b.signals) || []),
        ...(((_c = dep.execution) === null || _c === void 0 ? void 0 : _c.signals) || [])
    ]));
}
function maxRisk(risks) {
    if (risks.includes('red'))
        return 'red';
    if (risks.includes('amber'))
        return 'amber';
    return 'green';
}
function buildReportOverallRisk(dep, summary, supplyChainSignalCount = 0, supplyChainSignals, coverage) {
    var _a, _b, _c, _d, _e, _f, _g;
    const installRisk = ((_a = dep.execution) === null || _a === void 0 ? void 0 : _a.risk) || 'green';
    const combos = (0, supplyChainCombos_1.detectSupplyChainCombos)(dep, supplyChainSignalTypesForDep(dep, supplyChainSignals));
    const comboRisk = combos.some((combo) => combo.severity === 'error')
        ? 'red'
        : combos.length > 0
            ? 'amber'
            : 'green';
    const supplyChainRisk = supplyChainSignalCount > 0 || (((_c = (_b = dep.packaging) === null || _b === void 0 ? void 0 : _b.signals) === null || _c === void 0 ? void 0 : _c.length) || 0) > 0
        ? 'amber'
        : 'green';
    const registryRisk = (((_f = (_e = (_d = dep.supplyChain) === null || _d === void 0 ? void 0 : _d.registry) === null || _e === void 0 ? void 0 : _e.signals) === null || _f === void 0 ? void 0 : _f.length) || 0) > 0 ? 'amber' : 'green';
    const maintenanceStatus = (_g = dep.maintenance) === null || _g === void 0 ? void 0 : _g.status;
    // 'stale' deliberately does not escalate overall risk: 18 months without
    // registry writes is common for stable, finished packages. It stays a report
    // review cue (Maintenance badge, filter, key point, detail section), not a
    // dependency finding or CI fail rule.
    const maintenanceRisk = maintenanceStatus === 'deprecated' || maintenanceStatus === 'archived'
        ? 'red'
        : maintenanceStatus === 'unmaintained'
            ? 'amber'
            : 'green';
    const risk = maxRisk([
        summary.risk,
        dep.compliance.licenseRisk,
        installRisk,
        supplyChainRisk,
        comboRisk,
        registryRisk,
        maintenanceRisk
    ]);
    // Green means "checked and clean", so a package whose checks did not all run
    // reports 'unknown' instead. Amber and red are real findings and survive:
    // downgrading them to 'unknown' would hide evidence the scan did collect.
    const fullyChecked = (coverage === null || coverage === void 0 ? void 0 : coverage.auditVerified) !== false && (coverage === null || coverage === void 0 ? void 0 : coverage.contentsInspected) !== false;
    return risk === 'green' && !fullyChecked ? 'unknown' : risk;
}
/**
 * Build the supply-chain signal type set for one dependency instance, for
 * use with detectSupplyChainCombos.
 */
function supplyChainSignalTypesForDep(dep, signals) {
    if (!signals || signals.length === 0)
        return undefined;
    return (0, supplyChainCombos_1.signalTypesForDependency)((0, supplyChainCombos_1.indexSupplyChainSignalTypes)(signals), dep);
}
function titleCaseValue(value) {
    return value
        .split(/[-_\s]+/)
        .filter(Boolean)
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(' ');
}
function scopeLabel(scope) {
    if (scope === 'runtime')
        return 'Runtime';
    if (scope === 'dev')
        return 'Dev';
    if (scope === 'optional')
        return 'Optional';
    if (scope === 'peer')
        return 'Peer';
    return titleCaseValue(scope);
}
function toneLabel(tone) {
    if (tone === 'red')
        return 'High';
    if (tone === 'amber')
        return 'Medium';
    return 'Low';
}
function formatLicenseStatus(status) {
    switch (status) {
        case 'declared-only':
            return 'Declared';
        case 'inferred-only':
            return 'Inferred';
        case 'match':
            return 'Declared + Inferred (match)';
        case 'mismatch':
            return 'Declared + Inferred (mismatch)';
        case 'invalid-spdx':
            return 'Invalid SPDX';
        default:
            return 'Unknown';
    }
}
function formatModerateLow(summary) {
    const parts = [];
    if (summary.moderate)
        parts.push(`${summary.moderate} moderate`);
    if (summary.low)
        parts.push(`${summary.low} low`);
    return parts.join(', ');
}
function buildReportKeyPoints(dep, summary, supplyChainSignals, coverage) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s;
    const points = [];
    const vulnTotal = reportVulnerabilityTotal(summary);
    const hasFix = (_a = dep.security.advisories) === null || _a === void 0 ? void 0 : _a.some((adv) => adv.fixAvailable);
    if (summary.critical || summary.high) {
        const highTotal = summary.critical + summary.high;
        points.push(`${highTotal} critical/high ${highTotal === 1 ? 'vulnerability' : 'vulnerabilities'}${hasFix ? ', fix available' : ''}`);
    }
    if (summary.moderate || summary.low) {
        const lowerTotal = summary.moderate + summary.low;
        points.push(`${formatModerateLow(summary)} ${lowerTotal === 1 ? 'vulnerability' : 'vulnerabilities'}${hasFix ? ', fix available' : ''}`);
    }
    if (((_b = dep.maintenance) === null || _b === void 0 ? void 0 : _b.status) === 'deprecated') {
        points.push(dep.maintenance.deprecated && !dep.maintenance.deprecated.installedVersion
            ? 'Latest version deprecated by the author'
            : 'Deprecated by the author');
    }
    else if (((_c = dep.maintenance) === null || _c === void 0 ? void 0 : _c.status) === 'archived') {
        points.push('Source repository is archived');
    }
    else if (((_d = dep.maintenance) === null || _d === void 0 ? void 0 : _d.status) === 'unmaintained') {
        points.push(dep.maintenance.monthsSinceRepoPush !== undefined
            ? 'Registry and source repository have both gone quiet'
            : 'No registry activity for 3+ years');
    }
    else if (((_e = dep.maintenance) === null || _e === void 0 ? void 0 : _e.status) === 'stale') {
        points.push(dep.maintenance.monthsSinceRepoPush !== undefined
            ? 'Publishing and source activity have slowed to a trickle'
            : 'No registry activity for 18+ months');
    }
    else if (((_f = dep.maintenance) === null || _f === void 0 ? void 0 : _f.status) === 'slowing') {
        points.push('No registry publishes for 12+ months');
    }
    if (dep.compliance.licenseRisk !== 'green') {
        points.push('Licence status: ' + formatLicenseStatus(dep.compliance.license.status));
    }
    if (dep.upgrade.blocksNodeMajor)
        points.push('Blocks Node major upgrade');
    if ((_g = dep.upgrade.blockers) === null || _g === void 0 ? void 0 : _g.length) {
        points.push(`${dep.upgrade.blockers.length} upgrade ${dep.upgrade.blockers.length === 1 ? 'blocker' : 'blockers'} detected`);
    }
    (0, supplyChainCombos_1.detectSupplyChainCombos)(dep, supplyChainSignalTypesForDep(dep, supplyChainSignals)).forEach((combo) => points.push(combo.title));
    if (dep.replacement) {
        points.push('Community-suggested replacement available (e18e)');
    }
    const executionRisk = ((_h = dep.execution) === null || _h === void 0 ? void 0 : _h.risk) || 'green';
    if (executionRisk !== 'green')
        points.push(`${toneLabel(executionRisk)} install-time execution risk`);
    if ((_l = (_k = (_j = dep.execution) === null || _j === void 0 ? void 0 : _j.scripts) === null || _k === void 0 ? void 0 : _k.hooks) === null || _l === void 0 ? void 0 : _l.length) {
        points.push('Runs ' +
            dep.execution.scripts.hooks.slice(0, 2).join(', ') +
            ' lifecycle script' +
            (dep.execution.scripts.hooks.length === 1 ? '' : 's'));
    }
    reportAllExecutionSignals(dep)
        .slice(0, 3)
        .forEach((signal) => points.push(EXECUTION_SIGNAL_LABELS[signal]));
    if ((_o = (_m = dep.packaging) === null || _m === void 0 ? void 0 : _m.signals) === null || _o === void 0 ? void 0 : _o.length) {
        points.push(`${dep.packaging.signals.length} package content ${dep.packaging.signals.length === 1 ? 'signal' : 'signals'}`);
    }
    if ((_r = (_q = (_p = dep.supplyChain) === null || _p === void 0 ? void 0 : _p.registry) === null || _q === void 0 ? void 0 : _q.signals) === null || _r === void 0 ? void 0 : _r.length) {
        points.push(`${dep.supplyChain.registry.signals.length} registry metadata ${dep.supplyChain.registry.signals.length === 1 ? 'signal' : 'signals'}`);
    }
    if (dep.usage.direct) {
        points.push(`Direct ${scopeLabel(dep.usage.scope).toLowerCase()} dependency`);
    }
    else {
        const intro = ((_s = dep.usage.origins.topParentPackages) === null || _s === void 0 ? void 0 : _s[0])
            ? ` introduced by ${dep.usage.origins.topParentPackages[0]}`
            : '';
        points.push(`Transitive ${scopeLabel(dep.usage.scope).toLowerCase()} dependency${intro}`);
    }
    if (dep.usage.depth > 1)
        points.push(`Dependency depth ${dep.usage.depth}`);
    if (points.length === 0 || (vulnTotal === 0 && executionRisk === 'green' && dep.compliance.licenseRisk === 'green' && points.length < 3)) {
        const auditVerified = (coverage === null || coverage === void 0 ? void 0 : coverage.auditVerified) !== false;
        const contentsInspected = (coverage === null || coverage === void 0 ? void 0 : coverage.contentsInspected) !== false;
        [
            // Only a check that ran can report a clean result. Without these guards
            // a skipped audit still printed "No known vulnerabilities" directly
            // above a section reading "None reported (audit did not run)".
            auditVerified ? 'No known vulnerabilities' : '',
            contentsInspected ? 'No install-time execution signals detected' : '',
            'Licence status appears consistent',
            dep.usage.direct
                ? `Direct ${scopeLabel(dep.usage.scope).toLowerCase()} dependency`
                : `Transitive ${scopeLabel(dep.usage.scope).toLowerCase()} dependency`
        ].forEach((point) => {
            // startsWith, not equality: the specific form ("Transitive dev dependency
            // introduced by X") already covers the generic one, and listing both read
            // as a duplicate.
            if (point && !points.some((existing) => existing.startsWith(point))) {
                points.push(point);
            }
        });
    }
    return Array.from(new Set(points)).slice(0, 8);
}
