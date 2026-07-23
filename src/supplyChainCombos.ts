import type { DependencyRecord, ExecutionHook, SupplyChainSignal, SupplyChainSignalType } from './types';

// Combination flags: a package that runs code at install time is materially
// riskier when its source can change without a registry publish or cannot be
// integrity-checked. Each combo pairs install lifecycle hooks with one lockfile
// source signal so the report can explain why the pairing matters, not just
// list the two signals separately.

export type SupplyChainComboType =
  | 'install-scripts-git-source'
  | 'install-scripts-non-registry-tarball'
  | 'install-scripts-unexpected-registry-host'
  | 'install-scripts-missing-integrity';

export interface SupplyChainCombo {
  type: SupplyChainComboType;
  severity: 'warning' | 'error';
  signalType: SupplyChainSignalType;
  hooks: ExecutionHook[];
  title: string;
  detail: string;
}

const COMBO_RULES: Array<{
  signalType: SupplyChainSignalType;
  type: SupplyChainComboType;
  severity: 'warning' | 'error';
  title: string;
  detail: string;
}> = [
  {
    signalType: 'git-dependency',
    type: 'install-scripts-git-source',
    severity: 'error',
    title: 'Install scripts from a git-sourced package',
    detail: 'This package runs code at install time AND is installed from a git source, so its content can change without a version bump or registry publish.'
  },
  {
    signalType: 'non-registry-tarball',
    type: 'install-scripts-non-registry-tarball',
    severity: 'error',
    title: 'Install scripts from a non-registry tarball',
    detail: 'This package runs code at install time AND is fetched from a tarball outside the configured registry, bypassing registry review surfaces.'
  },
  {
    signalType: 'unexpected-registry-host',
    type: 'install-scripts-unexpected-registry-host',
    severity: 'error',
    title: 'Install scripts from an unexpected registry host',
    detail: 'This package runs code at install time AND resolves from a registry host that does not match the expected hosts for this project.'
  },
  {
    signalType: 'missing-integrity',
    type: 'install-scripts-missing-integrity',
    severity: 'warning',
    title: 'Install scripts without lockfile integrity',
    detail: 'This package runs code at install time AND has no lockfile integrity hash, so a substituted artifact would not be detected at install.'
  }
];

/**
 * Index project-level supply-chain signal types by package identity.
 *
 * Signals with a version-qualified identity (packageId, or packageName +
 * packageVersion) are keyed by it, so a source signal on one installed
 * version never implicates a different version of the same package. Signals
 * carrying only a bare package name are keyed by name as a best-effort
 * fallback and match every version.
 *
 * @param signals - The report's lockfile supply-chain signals, if any
 * @returns Map from package identity to the set of signal types observed
 */
export function indexSupplyChainSignalTypes(
  signals: SupplyChainSignal[] | undefined
): Map<string, Set<SupplyChainSignalType>> {
  const index = new Map<string, Set<SupplyChainSignalType>>();
  for (const signal of signals || []) {
    const key =
      signal.packageId ||
      (signal.packageName && signal.packageVersion
        ? `${signal.packageName}@${signal.packageVersion}`
        : signal.packageName);
    if (!key) continue;
    const types = index.get(key) || new Set<SupplyChainSignalType>();
    types.add(signal.type);
    index.set(key, types);
  }
  return index;
}

/**
 * Collect the signal types attributable to one dependency instance: exact
 * packageId first, then name@version, then version-less name-only signals.
 */
export function signalTypesForDependency(
  index: Map<string, Set<SupplyChainSignalType>>,
  dep: DependencyRecord
): Set<SupplyChainSignalType> | undefined {
  const keys = new Set([
    dep.package.id,
    `${dep.package.name}@${dep.package.version}`,
    dep.package.name
  ]);
  const merged = new Set<SupplyChainSignalType>();
  for (const key of keys) {
    index.get(key)?.forEach((type) => merged.add(type));
  }
  return merged.size > 0 ? merged : undefined;
}

/**
 * Detect install-script × source-signal combinations for one dependency.
 *
 * @param dep - The dependency record to inspect for install lifecycle hooks
 * @param signalTypes - Supply-chain signal types observed for this package name
 * @returns Combos ordered most severe first; empty when the package has no
 *   install hooks or no qualifying source signal
 */
export function detectSupplyChainCombos(
  dep: DependencyRecord,
  signalTypes: Set<SupplyChainSignalType> | undefined
): SupplyChainCombo[] {
  const hooks = dep.execution?.scripts?.hooks || [];
  if (hooks.length === 0 || !signalTypes || signalTypes.size === 0) return [];

  const combos: SupplyChainCombo[] = [];
  for (const rule of COMBO_RULES) {
    if (!signalTypes.has(rule.signalType)) continue;
    combos.push({
      type: rule.type,
      severity: rule.severity,
      signalType: rule.signalType,
      hooks: [...hooks].sort(),
      title: rule.title,
      detail: rule.detail
    });
  }
  return combos;
}
