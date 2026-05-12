import type { AggregatedData, DependencyRecord } from './types';

export type ExplainAvailability = 'available' | 'skipped' | 'unavailable';

export interface ExplainRenderContext {
  audit: ExplainAvailability;
  importGraphComplete: boolean;
}

const BLOCKER_LABELS: Record<string, string> = {
  nodeEngine: 'Node engine constraint',
  peerDependency: 'Peer dependency constraints',
  nativeBindings: 'Native bindings/build tooling',
  installScripts: 'Install lifecycle scripts',
  deprecated: 'Deprecated by author',
};

const EXECUTION_SIGNAL_LABELS: Record<string, string> = {
  'network-access': 'network access',
  'dynamic-exec': 'dynamic execution',
  'child-process': 'child process APIs',
  encoding: 'encoding/decoding logic',
  obfuscated: 'obfuscation-like code shape',
  'reads-env': 'environment access',
  'reads-home': 'home directory access',
  'uses-ssh': 'SSH-related references'
};

const PACKAGING_SIGNAL_LABELS: Record<string, string> = {
  'bundled-dependencies': 'bundled dependencies',
  'embedded-shrinkwrap': 'embedded npm-shrinkwrap.json'
};

export function findDependenciesByPackageName(
  aggregated: AggregatedData,
  packageName: string,
): DependencyRecord[] {
  return Object.values(aggregated.dependencies || {})
    .filter((dep) => dep.package.name === packageName)
    .sort((a, b) => {
      if (a.usage.direct !== b.usage.direct) {
        return a.usage.direct ? -1 : 1;
      }
      return compareVersionStrings(b.package.version, a.package.version);
    });
}

export function formatExplainOutput(
  packageName: string,
  matches: DependencyRecord[],
  context: ExplainRenderContext,
): string {
  if (matches.length === 0) {
    return `✖ Package not found: ${packageName}`;
  }

  const versions = Array.from(
    new Set(matches.map((dep) => dep.package.version)),
  ).sort((a, b) => compareVersionStrings(b, a));
  const lines: string[] = [];
  const header =
    versions.length > 1
      ? `${packageName} (${versions.length} versions detected)`
      : packageName;

  lines.push(header);
  lines.push('-'.repeat(Math.max(header.length, 24)));
  lines.push('');

  for (let index = 0; index < matches.length; index += 1) {
    const dep = matches[index];
    const staticImportEvidence = resolveStaticImportEvidence(dep, context);
    const vulnerabilitySummary = formatVulnerabilitySummary(dep, context.audit);
    const licenseSummary = formatLicenseSummary(dep);
    const otherVersions = versions.filter(
      (version) => version !== dep.package.version,
    );

    lines.push(dep.package.id);
    lines.push('');
    lines.push(`Type: ${dep.usage.direct ? 'direct' : 'transitive'}`);
    lines.push(`Scope: ${dep.usage.scope}`);
    lines.push(`Introduction: ${dep.usage.introduction || 'unknown'}`);
    lines.push(
      `Runtime impact: ${dep.usage.runtimeImpact || 'not detected'}`,
    );
    lines.push(`Static import evidence: ${staticImportEvidence}`);
    lines.push('');

    pushListSection(lines, 'Introduced via root packages', [
      ...dep.usage.origins.topRootPackages.map(
        (root) => `${root.name}@${root.version}`,
      ),
      ...formatOverflowLine(
        dep.usage.origins.rootPackageCount -
          dep.usage.origins.topRootPackages.length,
        'root packages',
      ),
    ], dep.usage.direct ? 'top-level dependency' : 'none identified');

    pushListSection(lines, 'Direct parents', [
      ...dep.usage.origins.topParentPackages,
      ...formatOverflowLine(
        dep.usage.origins.parentPackageCount -
          dep.usage.origins.topParentPackages.length,
        'parents',
      ),
    ], dep.usage.direct ? 'top-level dependency' : 'none identified');

    if (dep.usage.origins.workspaces?.length) {
      pushListSection(
        lines,
        'Workspaces',
        dep.usage.origins.workspaces,
        'none',
      );
    }

    if (dep.usage.importUsage?.topFiles?.length) {
      pushListSection(lines, 'Imported in', [
        ...dep.usage.importUsage.topFiles,
        ...formatOverflowLine(
          dep.usage.importUsage.fileCount - dep.usage.importUsage.topFiles.length,
          'files',
        ),
      ]);
    } else if (context.importGraphComplete) {
      lines.push('Imported in:');
      lines.push('  No static import references found');
    } else {
      lines.push('Imported in:');
      lines.push('  unavailable (import graph incomplete)');
    }
    lines.push('');

    lines.push('Vulnerabilities:');
    lines.push(`  ${vulnerabilitySummary}`);
    lines.push('');

    lines.push('License:');
    lines.push(`  ${licenseSummary}`);
    lines.push('');

    lines.push('Upgrade blockers:');
    if (dep.upgrade.blockers?.length) {
      for (const blocker of dep.upgrade.blockers) {
        lines.push(`  - ${BLOCKER_LABELS[blocker] || blocker}`);
      }
    } else {
      lines.push('  none');
    }

    lines.push('');
    lines.push('Local execution signals:');
    if (dep.execution?.signals?.length) {
      for (const signal of dep.execution.signals) {
        lines.push(`  - ${signal} (${EXECUTION_SIGNAL_LABELS[signal] || 'review signal'})`);
      }
    } else {
      lines.push('  none');
    }

    lines.push('');
    lines.push('Packaging signals:');
    if (dep.packaging?.signals?.length) {
      for (const signal of dep.packaging.signals) {
        lines.push(`  - ${signal} (${PACKAGING_SIGNAL_LABELS[signal] || 'review signal'})`);
      }
      if (dep.packaging.bundledDependencies?.length) {
        lines.push(`  bundled dependencies: ${dep.packaging.bundledDependencies.join(', ')}`);
      }
    } else {
      lines.push('  none');
    }

    if (otherVersions.length > 0) {
      lines.push('');
      lines.push('Other detected versions:');
      for (const version of otherVersions) {
        lines.push(`  ${version}`);
      }
    }

    if (index < matches.length - 1) {
      lines.push('');
      lines.push('');
    }
  }

  return lines.join('\n');
}

function pushListSection(
  lines: string[],
  label: string,
  values: string[],
  emptyFallback = 'none',
): void {
  lines.push(`${label}:`);
  if (values.length === 0) {
    lines.push(`  ${emptyFallback}`);
  } else {
    for (const value of values) {
      lines.push(`  ${value}`);
    }
  }
  lines.push('');
}

function formatOverflowLine(count: number, noun: string): string[] {
  if (count <= 0) return [];
  return [`+${count} more ${noun}`];
}

function resolveStaticImportEvidence(
  dep: DependencyRecord,
  context: ExplainRenderContext,
): string {
  if (dep.usage.importUsage?.fileCount) return 'yes';
  return context.importGraphComplete ? 'no' : 'unknown';
}

function formatVulnerabilitySummary(
  dep: DependencyRecord,
  availability: ExplainAvailability,
): string {
  if (availability === 'skipped') {
    return 'not available (--offline)';
  }
  if (availability === 'unavailable') {
    return 'not available (audit failed)';
  }

  const summary = dep.security.summary;
  const total =
    (summary.critical || 0) +
    (summary.high || 0) +
    (summary.moderate || 0) +
    (summary.low || 0);

  if (total === 0) return 'none';
  const advisoryLabel = total === 1 ? 'advisory' : 'advisories';
  return `${total} ${advisoryLabel} (highest severity: ${summary.highest})`;
}

function formatLicenseSummary(dep: DependencyRecord): string {
  const license = dep.compliance.license;
  const declared = license.declared?.spdxId;
  const inferred = license.inferred?.spdxId;

  switch (license.status) {
    case 'match':
      return `${declared || inferred || 'unknown'} (declared + inferred match)`;
    case 'declared-only':
      return `${declared || 'unknown'} (declared)`;
    case 'inferred-only':
      return `${inferred || 'unknown'} (inferred)`;
    case 'mismatch':
      return `mismatch (declared ${declared || 'unknown'}, inferred ${inferred || 'unknown'})`;
    case 'invalid-spdx':
      return `invalid SPDX (${declared || 'unknown'})`;
    default:
      return 'unknown';
  }
}

function compareVersionStrings(left: string, right: string): number {
  const leftParts = tokenizeVersion(left);
  const rightParts = tokenizeVersion(right);
  const maxLength = Math.max(leftParts.length, rightParts.length);

  for (let index = 0; index < maxLength; index += 1) {
    const leftPart = leftParts[index];
    const rightPart = rightParts[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    if (typeof leftPart === 'number' && typeof rightPart === 'number') {
      if (leftPart !== rightPart) return leftPart - rightPart;
      continue;
    }
    const compared = String(leftPart).localeCompare(String(rightPart));
    if (compared !== 0) return compared;
  }

  return left.localeCompare(right);
}

function tokenizeVersion(value: string): Array<number | string> {
  return value
    .split(/([0-9]+)/)
    .filter(Boolean)
    .map((part) => (/^[0-9]+$/.test(part) ? Number.parseInt(part, 10) : part));
}
