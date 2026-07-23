import type { AggregatedData, DependencyFinding, DependencyRecord, SupplyChainSignal } from './types';
import { isNodeEngineTargetCompatible } from './nodeEngine';
import { detectSupplyChainCombos, supplyChainSignalTypesByPackageName } from './supplyChainCombos';

function vulnerabilityTotal(dep: DependencyRecord): number {
  const summary = dep.security.summary;
  return (
    (summary.critical || 0) +
    (summary.high || 0) +
    (summary.moderate || 0) +
    (summary.low || 0)
  );
}

function findingId(dep: DependencyRecord, suffix: string): string {
  return `${dep.package.id}:${suffix}`.replace(/[^a-zA-Z0-9_.@/-]+/g, '-');
}

function supportsTargetNode(dep: DependencyRecord, targetNodeMajor: number | undefined): boolean | undefined {
  if (!targetNodeMajor || !dep.upgrade.nodeEngine) return undefined;
  return isNodeEngineTargetCompatible(dep.upgrade.nodeEngine, targetNodeMajor);
}

/**
 * Constructs a DependencyFinding by combining package identifiers derived from a dependency with the provided finding fields.
 *
 * @param dep - Dependency record used to derive `packageId`, `packageName`, `packageVersion`, and to generate the finding `id`.
 * @param suffix - Suffix appended to the package-based id to produce the finding `id`.
 * @param fields - Remaining `DependencyFinding` properties to include; must not contain `id`, `packageId`, `packageName`, or `packageVersion`.
 * @returns The assembled `DependencyFinding` with `id`, `packageId`, `packageName`, `packageVersion`, and the supplied fields.
 */
function baseFinding(
  dep: DependencyRecord,
  suffix: string,
  fields: Omit<DependencyFinding, 'id' | 'packageId' | 'packageName' | 'packageVersion'>
): DependencyFinding {
  return {
    id: findingId(dep, suffix),
    packageId: dep.package.id,
    packageName: dep.package.name,
    packageVersion: dep.package.version,
    ...fields
  };
}

/**
 * Produce the execution signals for a dependency after removing any signals that originate from install-only scripts.
 *
 * @param dep - Dependency record to inspect for execution signals and script-specific signals
 * @returns A sorted array of execution signal keys that are not associated with install-only scripts
 */
function withoutInstallOnlySignals(dep: DependencyRecord): string[] {
  const all = new Set(dep.execution?.signals || []);
  for (const signal of dep.execution?.scripts?.signals || []) {
    all.delete(signal);
  }
  return Array.from(all).sort();
}

const REGISTRY_SIGNAL_TITLES: Record<string, string> = {
  'recent-package': 'Recently created package',
  'recent-version': 'Recently published installed version',
  'low-release-history': 'Low release history',
  'reactivated-package': 'Package reactivated after dormancy',
  'old-major-new-patch': 'Recent patch on older major line'
};

/**
 * Convert aggregated dependency and supply-chain data into a sorted list of dependency findings.
 *
 * Processes each dependency and the supply-chain signals to emit findings for security, license/compliance,
 * execution and packaging signals, registry metadata, provenance/signature verification, and Node engine
 * compatibility relative to an optional target Node major version.
 *
 * @param data - Aggregated input containing `dependencies` and `supplyChain` information.
 * @param options.targetNodeMajor - If provided, emits findings when a dependency's declared Node engine
 *   does not appear to include the given major Node version.
 * @returns A list of DependencyFinding objects sorted by severity (error, warning, info), then by `packageId`, then by `id`.
 */
export function buildDependencyFindings(
  data: Pick<AggregatedData, 'dependencies' | 'supplyChain'>,
  options: { targetNodeMajor?: number } = {}
): DependencyFinding[] {
  const findings: DependencyFinding[] = [];
  const signalTypesByName = supplyChainSignalTypesByPackageName(data.supplyChain?.signals);

  for (const dep of Object.values(data.dependencies || {})) {
    const vulnCount = vulnerabilityTotal(dep);
    if (vulnCount > 0) {
      const highest = dep.security.summary.highest;
      findings.push(baseFinding(dep, 'vulnerabilities', {
        category: 'security',
        severity: highest === 'critical' || highest === 'high' ? 'error' : 'warning',
        title: `${vulnCount} known ${vulnCount === 1 ? 'vulnerability' : 'vulnerabilities'}`,
        message: `${dep.package.id} has audit advisories; highest severity is ${highest}.`,
        evidence: dep.security.advisories?.map((advisory) => advisory.id).join(', '),
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
        message: `${dep.package.id} declares ${dep.compliance.license.declared?.spdxId || 'unknown'} but the local license file looks like ${dep.compliance.license.inferred?.spdxId || 'unknown'}.`,
        recommendation: 'Verify the installed package license before release or compliance sign-off.'
      }));
    } else if (dep.compliance.license.status === 'invalid-spdx' || dep.compliance.license.status === 'unknown') {
      findings.push(baseFinding(dep, `license-${dep.compliance.license.status}`, {
        category: 'license',
        severity: dep.usage.scope === 'runtime' ? 'warning' : 'info',
        title: dep.compliance.license.status === 'unknown' ? 'License is unknown' : 'License declaration is invalid SPDX',
        message: `${dep.package.id} needs license review.`,
        evidence: dep.compliance.license.declared?.spdxId,
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

    if (dep.execution?.scripts?.hooks?.length) {
      findings.push(baseFinding(dep, 'install-scripts', {
        category: 'execution',
        severity: dep.execution.risk === 'red' ? 'error' : 'warning',
        title: 'Install lifecycle script',
        message: `${dep.package.id} runs ${dep.execution.scripts.hooks.join(', ')} during install.`,
        evidence: dep.execution.scripts.signals?.join(', '),
        recommendation: 'Review install-time behavior, especially in CI and release environments.'
      }));
    }

    const executionSignals = withoutInstallOnlySignals(dep);
    if (executionSignals.length > 0) {
      findings.push(baseFinding(dep, 'local-execution-signals', {
        category: 'execution',
        severity: 'warning',
        title: 'Local execution capability signal',
        message: `${dep.package.id} contains local execution capability signals that may warrant review.`,
        evidence: executionSignals.join(', '),
        recommendation: 'Review the referenced package entrypoints or executables and confirm this behavior is expected.'
      }));
    }

    if (dep.execution?.native) {
      findings.push(baseFinding(dep, 'native-bindings', {
        category: 'upgrade',
        severity: 'warning',
        title: 'Native binding or build surface',
        message: `${dep.package.id} includes native binding or native build indicators.`,
        recommendation: 'Check platform and Node major compatibility before upgrades.'
      }));
    }

    if (dep.package.deprecated) {
      const registryDeprecation = dep.maintenance?.deprecated;
      findings.push(baseFinding(dep, 'deprecated', {
        category: 'supply-chain',
        severity: dep.usage.scope === 'runtime' ? 'warning' : 'info',
        title: 'Package is deprecated',
        message: registryDeprecation
          ? registryDeprecation.installedVersion
            ? `${dep.package.id} is marked deprecated on the npm registry.`
            : `${dep.package.id}'s latest version is marked deprecated on the npm registry.`
          : `${dep.package.id} is marked deprecated in local package metadata.`,
        evidence: registryDeprecation?.message,
        recommendation: 'Plan migration to a maintained replacement.'
      }));
    }

    if (dep.maintenance?.status === 'archived') {
      findings.push(baseFinding(dep, 'maintenance-archived', {
        category: 'supply-chain',
        severity: dep.usage.scope === 'runtime' ? 'warning' : 'info',
        title: 'Source repository is archived',
        message: `${dep.package.id} points at an archived source repository, so fixes and security patches are unlikely.`,
        evidence: dep.maintenance.repoCheckedAt ? `repoCheckedAt=${dep.maintenance.repoCheckedAt}` : undefined,
        recommendation: 'Plan migration to a maintained replacement, or accept the risk explicitly.'
      }));
    }

    if (dep.maintenance?.status === 'unmaintained') {
      const monthsSinceModified = dep.maintenance.monthsSinceModified;
      findings.push(baseFinding(dep, 'maintenance-unmaintained', {
        category: 'supply-chain',
        severity: 'info',
        title: 'Package looks unmaintained',
        message: typeof monthsSinceModified === 'number'
          ? `${dep.package.id} has had no npm registry activity for ${monthsSinceModified} months.`
          : `${dep.package.id} has had no recent npm registry activity.`,
        evidence: dep.maintenance.packageModifiedAt ? `lastRegistryActivity=${dep.maintenance.packageModifiedAt}` : undefined,
        recommendation: 'Check whether the package is finished or abandoned, and review alternatives if it matters at runtime.'
      }));
    }

    for (const combo of detectSupplyChainCombos(dep, signalTypesByName.get(dep.package.name))) {
      findings.push(baseFinding(dep, combo.type, {
        category: 'supply-chain',
        severity: combo.severity,
        title: combo.title,
        message: `${dep.package.id}: ${combo.detail}`,
        evidence: `hooks=${combo.hooks.join(', ')}; signal=${combo.signalType}`,
        recommendation: 'Verify the dependency source and its install-time behavior, or move it to a registry-published, integrity-checked release.'
      }));
    }

    // Replacement suggestions stay informational and direct-only: a transitive
    // dependency is not directly actionable by the project maintainer.
    if (dep.replacement && dep.usage.direct) {
      findings.push(baseFinding(dep, 'replacement-available', {
        category: 'modernization',
        severity: 'info',
        title: 'Community-suggested replacement available',
        message: `${dep.package.id} could ${dep.replacement.type === 'native' ? 'be replaced by native functionality' : dep.replacement.type === 'simple' ? 'be replaced by a small inline snippet' : 'be replaced by a lighter alternative'}: ${dep.replacement.replacements.join(', ')}.`,
        evidence: dep.replacement.docUrl,
        recommendation: 'Suggestion from the e18e module-replacements catalogue; review fit before migrating.'
      }));
    }

    if (dep.packaging?.signals?.length) {
      findings.push(baseFinding(dep, 'packaging-signals', {
        category: 'supply-chain',
        severity: 'info',
        title: 'Package packaging review signal',
        message: `${dep.package.id} has packaging signals that may warrant review.`,
        evidence: dep.packaging.signals.join(', '),
        recommendation: 'Review package contents and confirm the packaging pattern is expected.'
      }));
    }

    for (const signal of dep.supplyChain?.registry?.signals || []) {
      const registry = dep.supplyChain?.registry;
      findings.push(baseFinding(dep, `registry-${signal}`, {
        category: 'supply-chain',
        severity: 'info',
        title: REGISTRY_SIGNAL_TITLES[signal] || 'Registry metadata review signal',
        message: `${dep.package.id} has npm registry metadata that may warrant review: ${signal}.`,
        evidence: [
          registry?.installedVersionPublishedAt ? `installedVersionPublishedAt=${registry.installedVersionPublishedAt}` : undefined,
          registry?.packageCreatedAt ? `packageCreatedAt=${registry.packageCreatedAt}` : undefined,
          typeof registry?.versionCount === 'number' ? `versionCount=${registry.versionCount}` : undefined,
          registry?.latestVersion ? `latest=${registry.latestVersion}` : undefined
        ].filter(Boolean).join('; '),
        recommendation: 'Review the package release history and confirm this registry activity is expected.'
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

  for (const signal of data.supplyChain?.signals || []) {
    findings.push(buildSupplyChainFinding(signal));
  }

  const signatureAudit = data.supplyChain?.signatureAudit;
  if (signatureAudit?.attempted && !signatureAudit.ok) {
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
    if (diff !== 0) return diff;
    return a.packageId.localeCompare(b.packageId) || a.id.localeCompare(b.id);
  });
}

function buildSupplyChainFinding(signal: SupplyChainSignal): DependencyFinding {
  const packageId = signal.packageId || (
    signal.packageName && signal.packageVersion
      ? `${signal.packageName}@${signal.packageVersion}`
      : signal.packageName || 'lockfile'
  );
  const titleByType: Record<SupplyChainSignal['type'], string> = {
    'git-dependency': 'Git dependency source',
    'file-dependency': 'Local file dependency source',
    'non-registry-tarball': 'Non-registry tarball source',
    'missing-integrity': 'Missing lockfile integrity',
    'unexpected-registry-host': 'Unexpected registry host'
  };
  const severity: DependencyFinding['severity'] =
    signal.type === 'missing-integrity' || signal.type === 'unexpected-registry-host'
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
