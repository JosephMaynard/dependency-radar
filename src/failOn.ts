import { validateSpdxExpression } from './license';
import { detectSupplyChainCombos, indexSupplyChainSignalTypes, signalTypesForDependency } from './supplyChainCombos';
import type { AggregatedData, DependencyRecord, ExecutionSignal, PackagingSignal, RegistryRiskSignal, SupplyChainSignal } from './types';

export type FailOnRule =
  | 'directly-imported-vuln'
  | 'reachable-vuln'
  | 'production-vuln'
  | 'high-severity-vuln'
  | 'licence-mismatch'
  | 'copyleft-detected'
  | 'unknown-licence'
  | 'supply-chain-source'
  | 'supply-chain-combo'
  | 'deprecated-dependency'
  | 'unmaintained-dependency'
  | 'new-deprecated'
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
  | 'new-shrinkwrap'
  | 'new-recent-package'
  | 'new-recent-version'
  | 'new-low-release-history'
  | 'new-reactivated-package'
  | 'new-old-major-patch';

export type PolicyViolation = {
  rule: FailOnRule;
  count: number;
  message: string;
  details?: string[];
};

export const SUPPORTED_FAIL_ON_RULES = [
  'directly-imported-vuln',
  'reachable-vuln',
  'production-vuln',
  'high-severity-vuln',
  'licence-mismatch',
  'copyleft-detected',
  'unknown-licence',
  'supply-chain-source',
  'supply-chain-combo',
  'deprecated-dependency',
  'unmaintained-dependency',
  'new-deprecated',
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
  'new-shrinkwrap',
  'new-recent-package',
  'new-recent-version',
  'new-low-release-history',
  'new-reactivated-package',
  'new-old-major-patch'
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

/**
 * Group dependency records by their package name.
 *
 * @param deps - Optional record of dependency entries keyed by dependency id; entries missing a package name are ignored
 * @returns A Map whose keys are package names and whose values are arrays of `DependencyRecord` objects for that package
 */
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

/**
 * Produce a package label for a dependency using its package id when available, otherwise `name@version`.
 *
 * @param dep - The dependency record whose package will be formatted
 * @returns The package `id` if present; otherwise the package `name` and `version` joined with `@`
 */
function formatPackage(dep: DependencyRecord): string {
  return dep.package.id || `${dep.package.name}@${dep.package.version}`;
}

/**
 * Retrieve the package's execution script hook names sorted lexicographically.
 *
 * @param dep - Dependency record to read hooks from
 * @returns The hook names from `dep.execution?.scripts?.hooks` sorted lexicographically; an empty array if no hooks are present
 */
function sortedHooks(dep: DependencyRecord): string[] {
  return [...(dep.execution?.scripts?.hooks || [])].sort();
}

/**
 * Collect execution-related signals from a dependency record.
 *
 * @param dep - The dependency record to inspect for execution signals
 * @returns A Set of unique `ExecutionSignal` values found on the dependency
 */
function executionSignals(dep: DependencyRecord): Set<ExecutionSignal> {
  return new Set([
    ...(dep.execution?.signals || []),
    ...(dep.execution?.scripts?.signals || [])
  ]);
}

/**
 * Collects packaging signals present on a dependency.
 *
 * @param dep - The dependency record to inspect
 * @returns A Set of `PackagingSignal` values found on `dep`; empty if the dependency has no packaging signals
 */
function packagingSignals(dep: DependencyRecord): Set<PackagingSignal> {
  return new Set(dep.packaging?.signals || []);
}

/**
 * Get the registry risk signals associated with a dependency.
 *
 * @param dep - The dependency record to inspect
 * @returns A Set of `RegistryRiskSignal` values found on the dependency's `supplyChain.registry.signals`; an empty `Set` if none are present
 */
function registrySignals(dep: DependencyRecord): Set<RegistryRiskSignal> {
  return new Set(dep.supplyChain?.registry?.signals || []);
}

/**
 * Extracts the package name associated with a supply-chain signal.
 *
 * Prefers `signal.packageName` when present; otherwise derives the name from
 * `signal.packageId` by taking the substring before the last `@`. Returns
 * `undefined` if neither value yields a usable package name.
 *
 * @param signal - The supply-chain signal to inspect
 * @returns The package name if present or derivable, `undefined` otherwise
 */
function signalPackageName(signal: SupplyChainSignal): string | undefined {
  if (signal.packageName) return signal.packageName;
  if (!signal.packageId) return undefined;
  const at = signal.packageId.lastIndexOf('@');
  if (at <= 0) return undefined;
  return signal.packageId.slice(0, at);
}

/**
 * Produce a human-readable package label for a supply-chain signal.
 *
 * @param signal - The supply-chain signal object used to derive the label.
 * @returns The label chosen in this priority: `signal.packageId`, `packageName@packageVersion`, `packageName`, or `'lockfile'` when no package information is available.
 */
function signalPackageLabel(signal: SupplyChainSignal): string {
  if (signal.packageId) return signal.packageId;
  if (signal.packageName && signal.packageVersion) return `${signal.packageName}@${signal.packageVersion}`;
  if (signal.packageName) return signal.packageName;
  return 'lockfile';
}

/**
 * Produce sets of observed supply-chain signal types, both per-package and globally.
 *
 * @param signals - Array of supply-chain signals to analyze; may be `undefined` or empty.
 * @returns An object with:
 *  - `byPackage`: map from package name to a `Set` of signal `type` strings observed for that package.
 *  - `global`: `Set` of all signal `type` strings observed (including those not tied to a package).
 */
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

/**
 * Appends a PolicyViolation for dependencies that newly exhibit the specified execution signal.
 *
 * If the provided `rule` is present in `rules` and one or more entries in `currentDeps`
 * have the `signal` while no previous dependency with the same package name had it,
 * a `PolicyViolation` describing the new execution signal(s) is pushed onto `violations`.
 *
 * @param violations - Mutable array to receive the generated PolicyViolation when matches are found
 * @param previousByName - Map of package name to previous DependencyRecord[] used as the baseline for comparison
 * @param currentDeps - Current dependency records to evaluate for newly introduced signals
 * @param rules - Set of enabled fail-on rules; the function is a no-op if `rule` is not in this set
 * @param rule - The specific FailOnRule to produce a violation for when triggered
 * @param signal - The ExecutionSignal to detect as newly introduced
 */
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

/**
 * Add a policy violation to `violations` when `signal` appears in current dependencies but was not present for the same package name in `previousByName`, and the given `rule` is enabled.
 *
 * @param violations - Accumulates discovered PolicyViolation objects; this function may push a new violation into it.
 * @param previousByName - Map from package name to previous scan DependencyRecord[] used to determine whether `signal` was already present for a package.
 * @param currentDeps - Current scan dependencies to inspect for newly introduced packaging signals.
 * @param rules - Selected fail-on rules; the function no-ops if `rule` is not in this set.
 * @param rule - The specific packaging-related compare-mode rule to enforce (e.g., `new-shrinkwrap` or `new-bundled-dependencies`).
 * @param signal - The PackagingSignal type to detect as newly introduced.
 */
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
 * Append a PolicyViolation for registry risk signals that appear in the current scan but were not present previously.
 *
 * If `rule` is not enabled in `rules`, this function does nothing. When enabled, it identifies current dependencies whose registry signals include `signal` and for which no previous dependency with the same package name had that signal, then pushes a violation with the total `count`, a summary `message`, and `details` listing affected packages.
 *
 * @param violations - Array to which the resulting PolicyViolation will be pushed
 * @param previousByName - Map of package name to list of previous DependencyRecord entries
 * @param currentDeps - List of current DependencyRecord entries to inspect
 * @param rules - Set of enabled fail-on rules
 * @param rule - The specific fail-on rule to check (must be present in `rules` to produce a violation)
 * @param signal - The registry risk signal to detect as newly introduced
 */
function pushNewRegistrySignalViolation(
  violations: PolicyViolation[],
  previousByName: Map<string, DependencyRecord[]>,
  currentDeps: DependencyRecord[],
  rules: Set<FailOnRule>,
  rule: FailOnRule,
  signal: RegistryRiskSignal
): void {
  if (!rules.has(rule)) return;
  const details = currentDeps
    .filter((dep) => {
      if (!registrySignals(dep).has(signal)) return false;
      return !(previousByName.get(dep.package.name) || []).some((previousDep) => registrySignals(previousDep).has(signal));
    })
    .map((dep) => `${formatPackage(dep)} introduced registry risk signal: ${signal}`)
    .sort();
  if (details.length === 0) return;
  violations.push({
    rule,
    count: details.length,
    message: `${details.length} new registry ${pluralize(details.length, 'risk signal', 'risk signals')}: ${signal}`,
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

  let directlyImportedProductionVulnCount = 0;
  let productionVulnCount = 0;
  let highSeverityVulnCount = 0;
  let licenceMismatchCount = 0;
  let copyleftDetectedCount = 0;
  let unknownLicenceCount = 0;
  let supplyChainSourceCount = 0;
  let deprecatedDependencyCount = 0;
  let unmaintainedDependencyCount = 0;

  for (const dep of Object.values(aggregated.dependencies || {})) {
    const isRuntime = dep.usage.scope === 'runtime';
    const hasVuln = vulnerabilityCount(dep) > 0;
    const isDirectlyImported = (dep.usage.importUsage?.fileCount || 0) > 0;
    const hasHighSeverityVuln =
      (dep.security.summary.high || 0) + (dep.security.summary.critical || 0) > 0;

    if (isRuntime && hasVuln && isDirectlyImported) {
      directlyImportedProductionVulnCount += 1;
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
    if (dep.package.deprecated) {
      deprecatedDependencyCount += 1;
    }
    if (dep.maintenance?.status === 'unmaintained' || dep.maintenance?.status === 'archived') {
      unmaintainedDependencyCount += 1;
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

  const directlyImportedRule = rules.has('directly-imported-vuln')
    ? 'directly-imported-vuln'
    : rules.has('reachable-vuln')
      ? 'reachable-vuln'
      : undefined;
  if (directlyImportedRule && directlyImportedProductionVulnCount > 0) {
    violations.push({
      rule: directlyImportedRule,
      count: directlyImportedProductionVulnCount,
      message: `${directlyImportedProductionVulnCount} directly imported production ${pluralize(
        directlyImportedProductionVulnCount,
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
  if (rules.has('supply-chain-combo')) {
    const signalTypeIndex = indexSupplyChainSignalTypes(aggregated.supplyChain?.signals);
    const details: string[] = [];
    for (const dep of Object.values(aggregated.dependencies || {})) {
      const combos = detectSupplyChainCombos(dep, signalTypesForDependency(signalTypeIndex, dep));
      for (const combo of combos) {
        details.push(`${formatPackage(dep)}: ${combo.title.toLowerCase()}`);
      }
    }
    details.sort();
    if (details.length > 0) {
      violations.push({
        rule: 'supply-chain-combo',
        count: details.length,
        message: `${details.length} install-script supply-chain ${pluralize(details.length, 'combination', 'combinations')}`,
        details
      });
    }
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
  if (rules.has('deprecated-dependency') && deprecatedDependencyCount > 0) {
    violations.push({
      rule: 'deprecated-dependency',
      count: deprecatedDependencyCount,
      message: `${deprecatedDependencyCount} deprecated ${pluralize(
        deprecatedDependencyCount,
        'dependency',
        'dependencies'
      )}`
    });
  }
  if (rules.has('unmaintained-dependency') && unmaintainedDependencyCount > 0) {
    violations.push({
      rule: 'unmaintained-dependency',
      count: unmaintainedDependencyCount,
      message: `${unmaintainedDependencyCount} unmaintained or archived ${pluralize(
        unmaintainedDependencyCount,
        'dependency',
        'dependencies'
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

  if (rules.has('new-deprecated')) {
    const details = currentDeps
      .filter((dep) => {
        if (!dep.package?.deprecated) return false;
        return !(previousByName.get(dep.package.name) || []).some((previousDep) => Boolean(previousDep.package?.deprecated));
      })
      .map((dep) => `${formatPackage(dep)} is now marked deprecated`)
      .sort();
    if (details.length > 0) {
      violations.push({
        rule: 'new-deprecated',
        count: details.length,
        message: `${details.length} newly deprecated ${pluralize(details.length, 'dependency', 'dependencies')}`,
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
  pushNewRegistrySignalViolation(violations, previousByName, currentDeps, rules, 'new-recent-package', 'recent-package');
  pushNewRegistrySignalViolation(violations, previousByName, currentDeps, rules, 'new-recent-version', 'recent-version');
  pushNewRegistrySignalViolation(violations, previousByName, currentDeps, rules, 'new-low-release-history', 'low-release-history');
  pushNewRegistrySignalViolation(violations, previousByName, currentDeps, rules, 'new-reactivated-package', 'reactivated-package');
  pushNewRegistrySignalViolation(violations, previousByName, currentDeps, rules, 'new-old-major-patch', 'old-major-new-patch');

  return violations;
}
