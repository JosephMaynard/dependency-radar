import { validateSpdxExpression } from './license';
import type { AggregatedData, DependencyRecord, ExecutionSignal, PackagingSignal, SupplyChainSignal } from './types';

export type FailOnRule =
  | 'reachable-vuln'
  | 'production-vuln'
  | 'high-severity-vuln'
  | 'licence-mismatch'
  | 'copyleft-detected'
  | 'unknown-licence'
  | 'supply-chain-source'
  | 'new-supply-chain-signal'
  | 'new-install-script'
  | 'new-native-binding'
  | 'new-bin'
  | 'new-direct-dependency'
  | 'new-child-process'
  | 'new-network-access'
  | 'new-env-access'
  | 'new-home-access'
  | 'new-ssh-usage'
  | 'new-obfuscation-signal'
  | 'new-bundled-dependencies'
  | 'new-shrinkwrap';

export type PolicyViolation = {
  rule: FailOnRule;
  count: number;
  message: string;
  details?: string[];
};

export const SUPPORTED_FAIL_ON_RULES = [
  'reachable-vuln',
  'production-vuln',
  'high-severity-vuln',
  'licence-mismatch',
  'copyleft-detected',
  'unknown-licence',
  'supply-chain-source',
  'new-supply-chain-signal',
  'new-install-script',
  'new-native-binding',
  'new-bin',
  'new-direct-dependency',
  'new-child-process',
  'new-network-access',
  'new-env-access',
  'new-home-access',
  'new-ssh-usage',
  'new-obfuscation-signal',
  'new-bundled-dependencies',
  'new-shrinkwrap'
] as const;

const SUPPORTED_FAIL_ON_RULE_SET = new Set<FailOnRule>(SUPPORTED_FAIL_ON_RULES);

/**
 * Choose the singular or plural form of a word based on a numeric value.
 *
 * @param value - The number used to decide singular versus plural
 * @param singular - The word form to use when `value` equals 1
 * @param plural - The word form to use when `value` does not equal 1
 * @returns The `singular` form if `value` equals 1, otherwise the `plural` form
 */
function pluralize(value: number, singular: string, plural: string): string {
  return value === 1 ? singular : plural;
}

/**
 * Compute the total number of vulnerabilities reported for a dependency.
 *
 * @param dep - The dependency record whose security summary will be aggregated
 * @returns The sum of `critical`, `high`, `moderate`, and `low` vulnerability counts
 */
function vulnerabilityCount(dep: DependencyRecord): number {
  return (
    (dep.security.summary.critical || 0) +
    (dep.security.summary.high || 0) +
    (dep.security.summary.moderate || 0) +
    (dep.security.summary.low || 0)
  );
}

function byPackageName(deps: Record<string, DependencyRecord> | undefined): Map<string, DependencyRecord[]> {
  const map = new Map<string, DependencyRecord[]>();
  for (const dep of Object.values(deps || {})) {
    const name = dep.package?.name;
    if (!name) continue;
    const entries = map.get(name) || [];
    entries.push(dep);
    map.set(name, entries);
  }
  return map;
}

function formatPackage(dep: DependencyRecord): string {
  return dep.package?.id || `${dep.package.name}@${dep.package.version}`;
}

function sortedHooks(dep: DependencyRecord): string[] {
  return [...(dep.execution?.scripts?.hooks || [])].sort();
}

function executionSignals(dep: DependencyRecord): Set<ExecutionSignal> {
  return new Set([
    ...(dep.execution?.signals || []),
    ...(dep.execution?.scripts?.signals || [])
  ]);
}

function packagingSignals(dep: DependencyRecord): Set<PackagingSignal> {
  return new Set(dep.packaging?.signals || []);
}

function signalPackageName(signal: SupplyChainSignal): string | undefined {
  if (signal.packageName) return signal.packageName;
  if (!signal.packageId) return undefined;
  const at = signal.packageId.lastIndexOf('@');
  if (at <= 0) return undefined;
  return signal.packageId.slice(0, at);
}

function signalPackageLabel(signal: SupplyChainSignal): string {
  if (signal.packageId) return signal.packageId;
  if (signal.packageName && signal.packageVersion) return `${signal.packageName}@${signal.packageVersion}`;
  if (signal.packageName) return signal.packageName;
  return 'lockfile';
}

function supplyChainSignalKeys(signals: SupplyChainSignal[] | undefined): {
  byPackage: Map<string, Set<string>>;
  global: Set<string>;
} {
  const byPackage = new Map<string, Set<string>>();
  const global = new Set<string>();
  for (const signal of signals || []) {
    global.add(signal.type);
    const name = signalPackageName(signal);
    if (!name) continue;
    const types = byPackage.get(name) || new Set<string>();
    types.add(signal.type);
    byPackage.set(name, types);
  }
  return { byPackage, global };
}

function pushNewExecutionSignalViolation(
  violations: PolicyViolation[],
  previousByName: Map<string, DependencyRecord[]>,
  currentDeps: DependencyRecord[],
  rules: Set<FailOnRule>,
  rule: FailOnRule,
  signal: ExecutionSignal
): void {
  if (!rules.has(rule)) return;
  const details = currentDeps
    .filter((dep) => {
      if (!executionSignals(dep).has(signal)) return false;
      return !(previousByName.get(dep.package.name) || []).some((previousDep) => executionSignals(previousDep).has(signal));
    })
    .map((dep) => `${formatPackage(dep)} introduced execution signal: ${signal}`)
    .sort();
  if (details.length === 0) return;
  violations.push({
    rule,
    count: details.length,
    message: `${details.length} new execution ${pluralize(details.length, 'signal', 'signals')}: ${signal}`,
    details
  });
}

function pushNewPackagingSignalViolation(
  violations: PolicyViolation[],
  previousByName: Map<string, DependencyRecord[]>,
  currentDeps: DependencyRecord[],
  rules: Set<FailOnRule>,
  rule: FailOnRule,
  signal: PackagingSignal
): void {
  if (!rules.has(rule)) return;
  const details = currentDeps
    .filter((dep) => {
      if (!packagingSignals(dep).has(signal)) return false;
      return !(previousByName.get(dep.package.name) || []).some((previousDep) => packagingSignals(previousDep).has(signal));
    })
    .map((dep) => `${formatPackage(dep)} introduced packaging signal: ${signal}`)
    .sort();
  if (details.length === 0) return;
  violations.push({
    rule,
    count: details.length,
    message: `${details.length} new packaging ${pluralize(details.length, 'signal', 'signals')}: ${signal}`,
    details
  });
}

/**
 * Detects whether a dependency has a strong copyleft license.
 *
 * @param dep - The dependency record to inspect for declared or inferred SPDX licenses
 * @returns `true` if any declared or inferred SPDX license ID indicates strong copyleft (GPL, AGPL, or variants), `false` otherwise.
 */
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

/**
 * Parse a comma-separated list of fail-on rule names into a validated set.
 *
 * @param value - Comma-separated rule names (e.g., "production-vuln,high-severity-vuln")
 * @returns A Set of validated `FailOnRule` values
 * @throws Error if `value` contains no rules or contains an unknown/unsupported rule
 */
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

/**
 * Compute policy violations from aggregated dependency data according to the provided fail-on rules.
 *
 * @param aggregated - Aggregated dependency data used to evaluate violations
 * @param rules - Set of active fail-on rules to check
 * @returns An array of PolicyViolation objects for each rule that has one or more matching issues; returns an empty array if no violations are found
 */
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
  let supplyChainSourceCount = 0;

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

  supplyChainSourceCount = (aggregated.supplyChain?.signals || []).filter((signal) =>
    signal.type === 'git-dependency' ||
    signal.type === 'file-dependency' ||
    signal.type === 'non-registry-tarball' ||
    signal.type === 'missing-integrity' ||
    signal.type === 'unexpected-registry-host'
  ).length;

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
  if (rules.has('supply-chain-source') && supplyChainSourceCount > 0) {
    violations.push({
      rule: 'supply-chain-source',
      count: supplyChainSourceCount,
      message: `${supplyChainSourceCount} ${pluralize(
        supplyChainSourceCount,
        'lockfile supply-chain source finding',
        'lockfile supply-chain source findings'
      )}`
    });
  }

  return violations;
}

/**
 * Compute compare-mode policy violations that focus on newly introduced risky traits.
 *
 * Delta rules compare the current scan against a previous Dependency Radar JSON report. They only fire
 * when a targeted trait appears in the current report and the baseline did not show that trait for the
 * same package name, or did not show that supply-chain signal type at all when a signal cannot be tied to
 * a package.
 */
export function evaluateComparePolicyViolations(
  previous: AggregatedData,
  current: AggregatedData,
  rules: Set<FailOnRule>
): PolicyViolation[] {
  if (rules.size === 0) return [];

  const previousByName = byPackageName(previous.dependencies);
  const currentDeps = Object.values(current.dependencies || {});
  const violations: PolicyViolation[] = [];

  if (rules.has('new-supply-chain-signal')) {
    const previousSignals = supplyChainSignalKeys(previous.supplyChain?.signals);
    const details = (current.supplyChain?.signals || [])
      .filter((signal) => {
        const name = signalPackageName(signal);
        if (name) return !previousSignals.byPackage.get(name)?.has(signal.type);
        return !previousSignals.global.has(signal.type);
      })
      .map((signal) => `${signalPackageLabel(signal)} introduced supply-chain signal: ${signal.type}`)
      .sort();
    if (details.length > 0) {
      violations.push({
        rule: 'new-supply-chain-signal',
        count: details.length,
        message: `${details.length} new supply-chain ${pluralize(details.length, 'signal', 'signals')}`,
        details
      });
    }
  }

  if (rules.has('new-install-script')) {
    const details = currentDeps
      .filter((dep) => {
        if (sortedHooks(dep).length === 0) return false;
        return !(previousByName.get(dep.package.name) || []).some((previousDep) => sortedHooks(previousDep).length > 0);
      })
      .map((dep) => `${formatPackage(dep)} introduced install hooks: ${sortedHooks(dep).join(', ')}`)
      .sort();
    if (details.length > 0) {
      violations.push({
        rule: 'new-install-script',
        count: details.length,
        message: `${details.length} new ${pluralize(details.length, 'install script surface', 'install script surfaces')}`,
        details
      });
    }
  }

  if (rules.has('new-native-binding')) {
    const details = currentDeps
      .filter((dep) => {
        if (!dep.execution?.native) return false;
        return !(previousByName.get(dep.package.name) || []).some((previousDep) => Boolean(previousDep.execution?.native));
      })
      .map((dep) => `${formatPackage(dep)} introduced native build/binary surface`)
      .sort();
    if (details.length > 0) {
      violations.push({
        rule: 'new-native-binding',
        count: details.length,
        message: `${details.length} new native ${pluralize(details.length, 'binding surface', 'binding surfaces')}`,
        details
      });
    }
  }

  if (rules.has('new-bin')) {
    const details = currentDeps
      .filter((dep) => {
        if (!dep.package?.hasBin) return false;
        return !(previousByName.get(dep.package.name) || []).some((previousDep) => Boolean(previousDep.package?.hasBin));
      })
      .map((dep) => `${formatPackage(dep)} introduced a package bin`)
      .sort();
    if (details.length > 0) {
      violations.push({
        rule: 'new-bin',
        count: details.length,
        message: `${details.length} new package ${pluralize(details.length, 'bin', 'bins')}`,
        details
      });
    }
  }

  if (rules.has('new-direct-dependency')) {
    const details = currentDeps
      .filter((dep) => {
        if (!dep.usage?.direct) return false;
        return !(previousByName.get(dep.package.name) || []).some((previousDep) => Boolean(previousDep.usage?.direct));
      })
      .map((dep) => `${formatPackage(dep)} is now a direct dependency`)
      .sort();
    if (details.length > 0) {
      violations.push({
        rule: 'new-direct-dependency',
        count: details.length,
        message: `${details.length} new direct ${pluralize(details.length, 'dependency', 'dependencies')}`,
        details
      });
    }
  }

  pushNewExecutionSignalViolation(violations, previousByName, currentDeps, rules, 'new-child-process', 'child-process');
  pushNewExecutionSignalViolation(violations, previousByName, currentDeps, rules, 'new-network-access', 'network-access');
  pushNewExecutionSignalViolation(violations, previousByName, currentDeps, rules, 'new-env-access', 'reads-env');
  pushNewExecutionSignalViolation(violations, previousByName, currentDeps, rules, 'new-home-access', 'reads-home');
  pushNewExecutionSignalViolation(violations, previousByName, currentDeps, rules, 'new-ssh-usage', 'uses-ssh');
  pushNewExecutionSignalViolation(violations, previousByName, currentDeps, rules, 'new-obfuscation-signal', 'obfuscated');
  pushNewPackagingSignalViolation(violations, previousByName, currentDeps, rules, 'new-bundled-dependencies', 'bundled-dependencies');
  pushNewPackagingSignalViolation(violations, previousByName, currentDeps, rules, 'new-shrinkwrap', 'embedded-shrinkwrap');

  return violations;
}
