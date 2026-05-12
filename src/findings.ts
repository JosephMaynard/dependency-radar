import type { AggregatedData, DependencyFinding, DependencyRecord, SupplyChainSignal } from './types';
import { isNodeEngineTargetCompatible } from './nodeEngine';

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

function withoutInstallOnlySignals(dep: DependencyRecord): string[] {
  const all = new Set(dep.execution?.signals || []);
  for (const signal of dep.execution?.scripts?.signals || []) {
    all.delete(signal);
  }
  return Array.from(all).sort();
}

export function buildDependencyFindings(
  data: Pick<AggregatedData, 'dependencies' | 'supplyChain'>,
  options: { targetNodeMajor?: number } = {}
): DependencyFinding[] {
  const findings: DependencyFinding[] = [];

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
      findings.push(baseFinding(dep, 'deprecated', {
        category: 'supply-chain',
        severity: dep.usage.scope === 'runtime' ? 'warning' : 'info',
        title: 'Package is deprecated',
        message: `${dep.package.id} is marked deprecated in local package metadata.`,
        recommendation: 'Plan migration to a maintained replacement.'
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
