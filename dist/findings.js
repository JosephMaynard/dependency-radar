"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildDependencyFindings = buildDependencyFindings;
function vulnerabilityTotal(dep) {
    const summary = dep.security.summary;
    return ((summary.critical || 0) +
        (summary.high || 0) +
        (summary.moderate || 0) +
        (summary.low || 0));
}
function findingId(dep, suffix) {
    return `${dep.package.id}:${suffix}`.replace(/[^a-zA-Z0-9_.@/-]+/g, '-');
}
function parseSupportedNodeMajors(range) {
    if (!range || !range.trim())
        return undefined;
    const majors = new Set();
    const clauses = range.split('||').map((clause) => clause.trim()).filter(Boolean);
    for (const clause of clauses) {
        const exacts = Array.from(clause.matchAll(/(?:^|[\s>=<~^])v?(\d+)(?:\.\d+)?(?:\.\d+)?/g))
            .map((match) => Number.parseInt(match[1], 10))
            .filter((major) => Number.isFinite(major));
        for (const major of exacts)
            majors.add(major);
        const lower = clause.match(/>=\s*v?(\d+)/);
        const upper = clause.match(/<\s*v?(\d+)/);
        if (lower && upper) {
            const start = Number.parseInt(lower[1], 10);
            const end = Number.parseInt(upper[1], 10);
            for (let major = start; major < end && major < start + 20; major += 1) {
                majors.add(major);
            }
        }
    }
    return majors.size > 0 ? majors : undefined;
}
function supportsTargetNode(dep, targetNodeMajor) {
    if (!targetNodeMajor || !dep.upgrade.nodeEngine)
        return undefined;
    const supportedMajors = parseSupportedNodeMajors(dep.upgrade.nodeEngine);
    if (!supportedMajors)
        return undefined;
    return supportedMajors.has(targetNodeMajor);
}
function baseFinding(dep, suffix, fields) {
    return {
        id: findingId(dep, suffix),
        packageId: dep.package.id,
        packageName: dep.package.name,
        packageVersion: dep.package.version,
        ...fields
    };
}
function buildDependencyFindings(data, options = {}) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
    const findings = [];
    for (const dep of Object.values(data.dependencies || {})) {
        const vulnCount = vulnerabilityTotal(dep);
        if (vulnCount > 0) {
            const highest = dep.security.summary.highest;
            findings.push(baseFinding(dep, 'vulnerabilities', {
                category: 'security',
                severity: highest === 'critical' || highest === 'high' ? 'error' : 'warning',
                title: `${vulnCount} known vulnerability${vulnCount === 1 ? '' : 'ies'}`,
                message: `${dep.package.id} has audit advisories; highest severity is ${highest}.`,
                evidence: (_a = dep.security.advisories) === null || _a === void 0 ? void 0 : _a.map((advisory) => advisory.id).join(', '),
                recommendation: dep.upgrade.latestVersion
                    ? `Review and upgrade toward ${dep.upgrade.latestVersion}.`
                    : 'Review the advisory and upgrade path.'
            }));
        }
        if (dep.compliance.license.status === 'mismatch') {
            findings.push(baseFinding(dep, 'license-mismatch', {
                category: 'license',
                severity: 'warning',
                title: 'Declared and inferred licenses differ',
                message: `${dep.package.id} declares ${((_b = dep.compliance.license.declared) === null || _b === void 0 ? void 0 : _b.spdxId) || 'unknown'} but the local license file looks like ${((_c = dep.compliance.license.inferred) === null || _c === void 0 ? void 0 : _c.spdxId) || 'unknown'}.`,
                recommendation: 'Verify the installed package license before release or compliance sign-off.'
            }));
        }
        else if (dep.compliance.license.status === 'invalid-spdx' || dep.compliance.license.status === 'unknown') {
            findings.push(baseFinding(dep, `license-${dep.compliance.license.status}`, {
                category: 'license',
                severity: dep.usage.scope === 'runtime' ? 'warning' : 'info',
                title: dep.compliance.license.status === 'unknown' ? 'License is unknown' : 'License declaration is invalid SPDX',
                message: `${dep.package.id} needs license review.`,
                evidence: (_d = dep.compliance.license.declared) === null || _d === void 0 ? void 0 : _d.spdxId,
                recommendation: 'Check package metadata and LICENSE files.'
            }));
        }
        if (dep.compliance.licenseRisk === 'red' && dep.usage.scope === 'runtime') {
            findings.push(baseFinding(dep, 'runtime-license-risk', {
                category: 'license',
                severity: 'error',
                title: 'High-risk runtime license',
                message: `${dep.package.id} is in the runtime tree and has red license risk.`,
                recommendation: 'Review legal/compliance acceptability or replace the package.'
            }));
        }
        if ((_g = (_f = (_e = dep.execution) === null || _e === void 0 ? void 0 : _e.scripts) === null || _f === void 0 ? void 0 : _f.hooks) === null || _g === void 0 ? void 0 : _g.length) {
            findings.push(baseFinding(dep, 'install-scripts', {
                category: 'execution',
                severity: dep.execution.risk === 'red' ? 'error' : 'warning',
                title: 'Install lifecycle script',
                message: `${dep.package.id} runs ${dep.execution.scripts.hooks.join(', ')} during install.`,
                evidence: (_h = dep.execution.scripts.signals) === null || _h === void 0 ? void 0 : _h.join(', '),
                recommendation: 'Review install-time behavior, especially in CI and release environments.'
            }));
        }
        if ((_j = dep.execution) === null || _j === void 0 ? void 0 : _j.native) {
            findings.push(baseFinding(dep, 'native-bindings', {
                category: 'upgrade',
                severity: 'warning',
                title: 'Native binding or build surface',
                message: `${dep.package.id} includes native binding or native build indicators.`,
                recommendation: 'Check platform and Node major compatibility before upgrades.'
            }));
        }
        if (dep.package.deprecated) {
            findings.push(baseFinding(dep, 'deprecated', {
                category: 'supply-chain',
                severity: dep.usage.scope === 'runtime' ? 'warning' : 'info',
                title: 'Package is deprecated',
                message: `${dep.package.id} is marked deprecated in local package metadata.`,
                recommendation: 'Plan migration to a maintained replacement.'
            }));
        }
        const targetSupport = supportsTargetNode(dep, options.targetNodeMajor);
        if (targetSupport === false && options.targetNodeMajor) {
            findings.push(baseFinding(dep, `target-node-${options.targetNodeMajor}`, {
                category: 'upgrade',
                severity: dep.usage.scope === 'runtime' ? 'error' : 'warning',
                title: `May block Node ${options.targetNodeMajor}`,
                message: `${dep.package.id} declares engines.node "${dep.upgrade.nodeEngine}", which does not appear to include Node ${options.targetNodeMajor}.`,
                recommendation: 'Upgrade, replace, or verify engine compatibility manually.'
            }));
        }
    }
    for (const signal of ((_k = data.supplyChain) === null || _k === void 0 ? void 0 : _k.signals) || []) {
        findings.push(buildSupplyChainFinding(signal));
    }
    const signatureAudit = (_l = data.supplyChain) === null || _l === void 0 ? void 0 : _l.signatureAudit;
    if ((signatureAudit === null || signatureAudit === void 0 ? void 0 : signatureAudit.attempted) && !signatureAudit.ok) {
        findings.push({
            id: 'supply-chain:signature-verification-failed',
            category: 'supply-chain',
            severity: 'warning',
            packageId: 'project',
            packageName: 'project',
            packageVersion: '',
            title: 'npm signature/provenance verification failed',
            message: signatureAudit.error || 'npm audit signatures did not complete successfully.',
            evidence: signatureAudit.output,
            recommendation: 'Review npm audit signatures output and verify registry/provenance status.'
        });
    }
    return findings.sort((a, b) => {
        const severityOrder = { error: 2, warning: 1, info: 0 };
        const diff = severityOrder[b.severity] - severityOrder[a.severity];
        if (diff !== 0)
            return diff;
        return a.packageId.localeCompare(b.packageId) || a.id.localeCompare(b.id);
    });
}
function buildSupplyChainFinding(signal) {
    const packageId = signal.packageId || (signal.packageName && signal.packageVersion
        ? `${signal.packageName}@${signal.packageVersion}`
        : signal.packageName || 'lockfile');
    const titleByType = {
        'git-dependency': 'Git dependency source',
        'file-dependency': 'Local file dependency source',
        'non-registry-tarball': 'Non-registry tarball source',
        'missing-integrity': 'Missing lockfile integrity',
        'unexpected-registry-host': 'Unexpected registry host',
        'signature-verification-failed': 'Signature verification failed',
        'signature-verification-unavailable': 'Signature verification unavailable'
    };
    const severity = signal.type === 'missing-integrity' || signal.type === 'unexpected-registry-host'
        ? 'warning'
        : 'info';
    return {
        id: `${packageId}:${signal.type}`.replace(/[^a-zA-Z0-9_.@/-]+/g, '-'),
        category: 'supply-chain',
        severity,
        packageId,
        packageName: signal.packageName || packageId,
        packageVersion: signal.packageVersion || '',
        title: titleByType[signal.type],
        message: signal.detail,
        evidence: signal.source,
        recommendation: 'Review the dependency source and confirm it is expected for this project.'
    };
}
