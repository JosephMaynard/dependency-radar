"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SUPPORTED_FAIL_ON_RULES = void 0;
exports.parseFailOnRules = parseFailOnRules;
exports.evaluatePolicyViolations = evaluatePolicyViolations;
const license_1 = require("./license");
exports.SUPPORTED_FAIL_ON_RULES = [
    'reachable-vuln',
    'production-vuln',
    'high-severity-vuln',
    'licence-mismatch',
    'copyleft-detected',
    'unknown-licence',
    'supply-chain-source'
];
const SUPPORTED_FAIL_ON_RULE_SET = new Set(exports.SUPPORTED_FAIL_ON_RULES);
/**
 * Choose the singular or plural form of a word based on a numeric value.
 *
 * @param value - The number used to decide singular versus plural
 * @param singular - The word form to use when `value` equals 1
 * @param plural - The word form to use when `value` does not equal 1
 * @returns The `singular` form if `value` equals 1, otherwise the `plural` form
 */
function pluralize(value, singular, plural) {
    return value === 1 ? singular : plural;
}
/**
 * Compute the total number of vulnerabilities reported for a dependency.
 *
 * @param dep - The dependency record whose security summary will be aggregated
 * @returns The sum of `critical`, `high`, `moderate`, and `low` vulnerability counts
 */
function vulnerabilityCount(dep) {
    return ((dep.security.summary.critical || 0) +
        (dep.security.summary.high || 0) +
        (dep.security.summary.moderate || 0) +
        (dep.security.summary.low || 0));
}
/**
 * Detects whether a dependency has a strong copyleft license.
 *
 * @param dep - The dependency record to inspect for declared or inferred SPDX licenses
 * @returns `true` if any declared or inferred SPDX license ID indicates strong copyleft (GPL, AGPL, or variants), `false` otherwise.
 */
function hasStrongCopyleftLicense(dep) {
    var _a, _b;
    const ids = new Set();
    const declaredSpdx = (_a = dep.compliance.license.declared) === null || _a === void 0 ? void 0 : _a.spdxId;
    if (declaredSpdx) {
        const parsed = (0, license_1.validateSpdxExpression)(declaredSpdx);
        if (parsed.valid) {
            for (const id of parsed.licenseIds) {
                ids.add(id.toUpperCase());
            }
        }
    }
    const inferredSpdx = (_b = dep.compliance.license.inferred) === null || _b === void 0 ? void 0 : _b.spdxId;
    if (inferredSpdx) {
        ids.add(inferredSpdx.toUpperCase());
    }
    for (const id of ids) {
        if (id === 'GPL' || id === 'AGPL' || id.startsWith('GPL-') || id.startsWith('AGPL-')) {
            return true;
        }
    }
    return false;
}
/**
 * Parse a comma-separated list of fail-on rule names into a validated set.
 *
 * @param value - Comma-separated rule names (e.g., "production-vuln,high-severity-vuln")
 * @returns A Set of validated `FailOnRule` values
 * @throws Error if `value` contains no rules or contains an unknown/unsupported rule
 */
function parseFailOnRules(value) {
    const selected = new Set();
    const rawRules = value
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean);
    if (rawRules.length === 0) {
        throw new Error(`No --fail-on rules provided. Supported rules: ${exports.SUPPORTED_FAIL_ON_RULES.join(', ')}`);
    }
    for (const rule of rawRules) {
        if (!SUPPORTED_FAIL_ON_RULE_SET.has(rule)) {
            throw new Error(`Unknown --fail-on rule: "${rule}". Supported rules: ${exports.SUPPORTED_FAIL_ON_RULES.join(', ')}`);
        }
        selected.add(rule);
    }
    return selected;
}
/**
 * Compute policy violations from aggregated dependency data according to the provided fail-on rules.
 *
 * @param aggregated - Aggregated dependency data used to evaluate violations
 * @param rules - Set of active fail-on rules to check
 * @returns An array of PolicyViolation objects for each rule that has one or more matching issues; returns an empty array if no violations are found
 */
function evaluatePolicyViolations(aggregated, rules) {
    var _a, _b;
    if (rules.size === 0)
        return [];
    let reachableProductionVulnCount = 0;
    let productionVulnCount = 0;
    let highSeverityVulnCount = 0;
    let licenceMismatchCount = 0;
    let copyleftDetectedCount = 0;
    let unknownLicenceCount = 0;
    let supplyChainSourceCount = 0;
    for (const dep of Object.values(aggregated.dependencies || {})) {
        const isRuntime = dep.usage.scope === 'runtime';
        const hasVuln = vulnerabilityCount(dep) > 0;
        const isReachable = (((_a = dep.usage.importUsage) === null || _a === void 0 ? void 0 : _a.fileCount) || 0) > 0;
        const hasHighSeverityVuln = (dep.security.summary.high || 0) + (dep.security.summary.critical || 0) > 0;
        if (isRuntime && hasVuln && isReachable) {
            reachableProductionVulnCount += 1;
        }
        if (isRuntime && hasVuln) {
            productionVulnCount += 1;
        }
        if (hasHighSeverityVuln) {
            highSeverityVulnCount += 1;
        }
        if (dep.compliance.license.status === 'mismatch') {
            licenceMismatchCount += 1;
        }
        if (isRuntime && hasStrongCopyleftLicense(dep)) {
            copyleftDetectedCount += 1;
        }
        if (!dep.compliance.license.declared && !dep.compliance.license.inferred) {
            unknownLicenceCount += 1;
        }
    }
    supplyChainSourceCount = (((_b = aggregated.supplyChain) === null || _b === void 0 ? void 0 : _b.signals) || []).filter((signal) => signal.type === 'git-dependency' ||
        signal.type === 'file-dependency' ||
        signal.type === 'non-registry-tarball' ||
        signal.type === 'missing-integrity' ||
        signal.type === 'unexpected-registry-host').length;
    const violations = [];
    if (rules.has('reachable-vuln') && reachableProductionVulnCount > 0) {
        violations.push({
            rule: 'reachable-vuln',
            count: reachableProductionVulnCount,
            message: `${reachableProductionVulnCount} reachable production ${pluralize(reachableProductionVulnCount, 'vulnerability', 'vulnerabilities')}`
        });
    }
    if (rules.has('production-vuln') && productionVulnCount > 0) {
        violations.push({
            rule: 'production-vuln',
            count: productionVulnCount,
            message: `${productionVulnCount} production ${pluralize(productionVulnCount, 'vulnerability', 'vulnerabilities')}`
        });
    }
    if (rules.has('high-severity-vuln') && highSeverityVulnCount > 0) {
        violations.push({
            rule: 'high-severity-vuln',
            count: highSeverityVulnCount,
            message: `${highSeverityVulnCount} high-severity ${pluralize(highSeverityVulnCount, 'vulnerability', 'vulnerabilities')}`
        });
    }
    if (rules.has('licence-mismatch') && licenceMismatchCount > 0) {
        violations.push({
            rule: 'licence-mismatch',
            count: licenceMismatchCount,
            message: `${licenceMismatchCount} ${pluralize(licenceMismatchCount, 'licence mismatch', 'licence mismatches')}`
        });
    }
    if (rules.has('copyleft-detected') && copyleftDetectedCount > 0) {
        violations.push({
            rule: 'copyleft-detected',
            count: copyleftDetectedCount,
            message: `Copyleft licence detected in runtime tree (${copyleftDetectedCount} ${pluralize(copyleftDetectedCount, 'package', 'packages')})`
        });
    }
    if (rules.has('unknown-licence') && unknownLicenceCount > 0) {
        violations.push({
            rule: 'unknown-licence',
            count: unknownLicenceCount,
            message: `${unknownLicenceCount} ${pluralize(unknownLicenceCount, 'dependency with unknown licence', 'dependencies with unknown licence')}`
        });
    }
    if (rules.has('supply-chain-source') && supplyChainSourceCount > 0) {
        violations.push({
            rule: 'supply-chain-source',
            count: supplyChainSourceCount,
            message: `${supplyChainSourceCount} ${pluralize(supplyChainSourceCount, 'lockfile supply-chain source finding', 'lockfile supply-chain source findings')}`
        });
    }
    return violations;
}
