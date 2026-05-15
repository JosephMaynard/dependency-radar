"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.reportVulnerabilityTotal = reportVulnerabilityTotal;
exports.reportAllExecutionSignals = reportAllExecutionSignals;
exports.buildReportOverallRisk = buildReportOverallRisk;
exports.buildReportKeyPoints = buildReportKeyPoints;
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
function buildReportOverallRisk(dep, summary, supplyChainSignalCount = 0) {
    var _a, _b, _c, _d, _e, _f;
    const installRisk = ((_a = dep.execution) === null || _a === void 0 ? void 0 : _a.risk) || 'green';
    const supplyChainRisk = supplyChainSignalCount > 0 || (((_c = (_b = dep.packaging) === null || _b === void 0 ? void 0 : _b.signals) === null || _c === void 0 ? void 0 : _c.length) || 0) > 0
        ? 'amber'
        : 'green';
    const maintenanceRisk = (((_f = (_e = (_d = dep.supplyChain) === null || _d === void 0 ? void 0 : _d.registry) === null || _e === void 0 ? void 0 : _e.signals) === null || _f === void 0 ? void 0 : _f.length) || 0) > 0 ? 'amber' : 'green';
    return maxRisk([
        summary.risk,
        dep.compliance.licenseRisk,
        installRisk,
        supplyChainRisk,
        maintenanceRisk
    ]);
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
function buildReportKeyPoints(dep, summary) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m;
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
    if (dep.compliance.licenseRisk !== 'green') {
        points.push('Licence status: ' + formatLicenseStatus(dep.compliance.license.status));
    }
    if (dep.upgrade.blocksNodeMajor)
        points.push('Blocks Node major upgrade');
    if ((_b = dep.upgrade.blockers) === null || _b === void 0 ? void 0 : _b.length) {
        points.push(`${dep.upgrade.blockers.length} upgrade ${dep.upgrade.blockers.length === 1 ? 'blocker' : 'blockers'} detected`);
    }
    const executionRisk = ((_c = dep.execution) === null || _c === void 0 ? void 0 : _c.risk) || 'green';
    if (executionRisk !== 'green')
        points.push(`${toneLabel(executionRisk)} install-time execution risk`);
    if ((_f = (_e = (_d = dep.execution) === null || _d === void 0 ? void 0 : _d.scripts) === null || _e === void 0 ? void 0 : _e.hooks) === null || _f === void 0 ? void 0 : _f.length) {
        points.push('Runs ' +
            dep.execution.scripts.hooks.slice(0, 2).join(', ') +
            ' lifecycle script' +
            (dep.execution.scripts.hooks.length === 1 ? '' : 's'));
    }
    reportAllExecutionSignals(dep)
        .slice(0, 3)
        .forEach((signal) => points.push(EXECUTION_SIGNAL_LABELS[signal]));
    if ((_h = (_g = dep.packaging) === null || _g === void 0 ? void 0 : _g.signals) === null || _h === void 0 ? void 0 : _h.length) {
        points.push(`${dep.packaging.signals.length} package content ${dep.packaging.signals.length === 1 ? 'signal' : 'signals'}`);
    }
    if ((_l = (_k = (_j = dep.supplyChain) === null || _j === void 0 ? void 0 : _j.registry) === null || _k === void 0 ? void 0 : _k.signals) === null || _l === void 0 ? void 0 : _l.length) {
        points.push(`${dep.supplyChain.registry.signals.length} registry metadata ${dep.supplyChain.registry.signals.length === 1 ? 'signal' : 'signals'}`);
    }
    if (dep.usage.direct) {
        points.push(`Direct ${scopeLabel(dep.usage.scope).toLowerCase()} dependency`);
    }
    else {
        const intro = ((_m = dep.usage.origins.topParentPackages) === null || _m === void 0 ? void 0 : _m[0])
            ? ` introduced by ${dep.usage.origins.topParentPackages[0]}`
            : '';
        points.push(`Transitive ${scopeLabel(dep.usage.scope).toLowerCase()} dependency${intro}`);
    }
    if (dep.usage.depth > 1)
        points.push(`Dependency depth ${dep.usage.depth}`);
    if (points.length === 0 || (vulnTotal === 0 && executionRisk === 'green' && dep.compliance.licenseRisk === 'green' && points.length < 3)) {
        [
            'No known vulnerabilities',
            'No install-time execution signals detected',
            'Licence status appears consistent',
            dep.usage.direct
                ? `Direct ${scopeLabel(dep.usage.scope).toLowerCase()} dependency`
                : `Transitive ${scopeLabel(dep.usage.scope).toLowerCase()} dependency`
        ].forEach((point) => {
            if (!points.includes(point))
                points.push(point);
        });
    }
    return Array.from(new Set(points)).slice(0, 8);
}
