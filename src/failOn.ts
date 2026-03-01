import { validateSpdxExpression } from './license';
import type { AggregatedData, DependencyRecord } from './types';

export type FailOnRule =
  | 'reachable-vuln'
  | 'production-vuln'
  | 'high-severity-vuln'
  | 'licence-mismatch'
  | 'copyleft-detected'
  | 'unknown-licence';

export type PolicyViolation = {
  rule: FailOnRule;
  count: number;
  message: string;
};

export const SUPPORTED_FAIL_ON_RULES = [
  'reachable-vuln',
  'production-vuln',
  'high-severity-vuln',
  'licence-mismatch',
  'copyleft-detected',
  'unknown-licence'
] as const;

const SUPPORTED_FAIL_ON_RULE_SET = new Set<FailOnRule>(SUPPORTED_FAIL_ON_RULES);

function pluralize(value: number, singular: string, plural: string): string {
  return value === 1 ? singular : plural;
}

function vulnerabilityCount(dep: DependencyRecord): number {
  return (
    (dep.security.summary.critical || 0) +
    (dep.security.summary.high || 0) +
    (dep.security.summary.moderate || 0) +
    (dep.security.summary.low || 0)
  );
}

function hasStrongCopyleftLicense(dep: DependencyRecord): boolean {
  const ids = new Set<string>();
  const declaredSpdx = dep.compliance.license.declared?.spdxId;
  if (declaredSpdx) {
    const parsed = validateSpdxExpression(declaredSpdx);
    if (parsed.valid) {
      for (const id of parsed.licenseIds) {
        ids.add(id.toUpperCase());
      }
    }
  }
  const inferredSpdx = dep.compliance.license.inferred?.spdxId;
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

export function parseFailOnRules(value: string): Set<FailOnRule> {
  const selected = new Set<FailOnRule>();
  const rawRules = value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

  if (rawRules.length === 0) {
    throw new Error(
      `No --fail-on rules provided. Supported rules: ${SUPPORTED_FAIL_ON_RULES.join(', ')}`
    );
  }

  for (const rule of rawRules) {
    if (!SUPPORTED_FAIL_ON_RULE_SET.has(rule as FailOnRule)) {
      throw new Error(
        `Unknown --fail-on rule: "${rule}". Supported rules: ${SUPPORTED_FAIL_ON_RULES.join(', ')}`
      );
    }
    selected.add(rule as FailOnRule);
  }

  return selected;
}

export function evaluatePolicyViolations(
  aggregated: AggregatedData,
  rules: Set<FailOnRule>
): PolicyViolation[] {
  if (rules.size === 0) return [];

  let reachableProductionVulnCount = 0;
  let productionVulnCount = 0;
  let highSeverityVulnCount = 0;
  let licenceMismatchCount = 0;
  let copyleftDetectedCount = 0;
  let unknownLicenceCount = 0;

  for (const dep of Object.values(aggregated.dependencies || {})) {
    const isRuntime = dep.usage.scope === 'runtime';
    const hasVuln = vulnerabilityCount(dep) > 0;
    const isReachable = (dep.usage.importUsage?.fileCount || 0) > 0;
    const hasHighSeverityVuln =
      (dep.security.summary.high || 0) + (dep.security.summary.critical || 0) > 0;

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

  const violations: PolicyViolation[] = [];

  if (rules.has('reachable-vuln') && reachableProductionVulnCount > 0) {
    violations.push({
      rule: 'reachable-vuln',
      count: reachableProductionVulnCount,
      message: `${reachableProductionVulnCount} reachable production ${pluralize(
        reachableProductionVulnCount,
        'vulnerability',
        'vulnerabilities'
      )}`
    });
  }
  if (rules.has('production-vuln') && productionVulnCount > 0) {
    violations.push({
      rule: 'production-vuln',
      count: productionVulnCount,
      message: `${productionVulnCount} production ${pluralize(
        productionVulnCount,
        'vulnerability',
        'vulnerabilities'
      )}`
    });
  }
  if (rules.has('high-severity-vuln') && highSeverityVulnCount > 0) {
    violations.push({
      rule: 'high-severity-vuln',
      count: highSeverityVulnCount,
      message: `${highSeverityVulnCount} high-severity ${pluralize(
        highSeverityVulnCount,
        'vulnerability',
        'vulnerabilities'
      )}`
    });
  }
  if (rules.has('licence-mismatch') && licenceMismatchCount > 0) {
    violations.push({
      rule: 'licence-mismatch',
      count: licenceMismatchCount,
      message: `${licenceMismatchCount} ${pluralize(
        licenceMismatchCount,
        'licence mismatch',
        'licence mismatches'
      )}`
    });
  }
  if (rules.has('copyleft-detected') && copyleftDetectedCount > 0) {
    violations.push({
      rule: 'copyleft-detected',
      count: copyleftDetectedCount,
      message: `Copyleft licence detected in runtime tree (${copyleftDetectedCount} ${pluralize(
        copyleftDetectedCount,
        'package',
        'packages'
      )})`
    });
  }
  if (rules.has('unknown-licence') && unknownLicenceCount > 0) {
    violations.push({
      rule: 'unknown-licence',
      count: unknownLicenceCount,
      message: `${unknownLicenceCount} ${pluralize(
        unknownLicenceCount,
        'dependency with unknown licence',
        'dependencies with unknown licence'
      )}`
    });
  }

  return violations;
}
