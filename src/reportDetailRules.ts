import type { DependencyRecord, ExecutionSignal, Severity } from './types';

export type SecuritySummary = {
  critical: number;
  high: number;
  moderate: number;
  low: number;
  highest: Severity | 'none';
  risk: 'green' | 'amber' | 'red';
};

const EXECUTION_SIGNAL_LABELS: Record<ExecutionSignal, string> = {
  'network-access': 'Accesses network during install',
  'dynamic-exec': 'Uses dynamic execution',
  'child-process': 'Spawns child processes',
  encoding: 'Uses encoding/decoding logic',
  obfuscated: 'Contains obfuscated/minified install logic',
  'reads-env': 'Reads environment variables',
  'reads-home': 'Reads user home directory',
  'uses-ssh': 'Uses SSH configuration/keys'
};

export function reportVulnerabilityTotal(summary: SecuritySummary): number {
  return summary.critical + summary.high + summary.moderate + summary.low;
}

export function reportAllExecutionSignals(dep: DependencyRecord): ExecutionSignal[] {
  return Array.from(
    new Set([
      ...(dep.execution?.scripts?.signals || []),
      ...(dep.execution?.signals || [])
    ])
  );
}

function titleCaseValue(value: string): string {
  return value
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function scopeLabel(scope: string): string {
  if (scope === 'runtime') return 'Runtime';
  if (scope === 'dev') return 'Dev';
  if (scope === 'optional') return 'Optional';
  if (scope === 'peer') return 'Peer';
  return titleCaseValue(scope);
}

function toneLabel(tone?: 'red' | 'amber' | 'green'): string {
  if (tone === 'red') return 'High';
  if (tone === 'amber') return 'Medium';
  return 'Low';
}

function formatLicenseStatus(status: DependencyRecord['compliance']['license']['status']): string {
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

function formatModerateLow(summary: SecuritySummary): string {
  const parts: string[] = [];
  if (summary.moderate) parts.push(`${summary.moderate} moderate`);
  if (summary.low) parts.push(`${summary.low} low`);
  return parts.join(', ');
}

export function buildReportKeyPoints(dep: DependencyRecord, summary: SecuritySummary): string[] {
  const points: string[] = [];
  const vulnTotal = reportVulnerabilityTotal(summary);
  const hasFix = dep.security.advisories?.some((adv) => adv.fixAvailable);
  if (summary.critical || summary.high) {
    const highTotal = summary.critical + summary.high;
    points.push(
      `${highTotal} critical/high ${highTotal === 1 ? 'vulnerability' : 'vulnerabilities'}${hasFix ? ', fix available' : ''}`
    );
  }
  if (summary.moderate || summary.low) {
    const lowerTotal = summary.moderate + summary.low;
    points.push(
      `${formatModerateLow(summary)} ${lowerTotal === 1 ? 'vulnerability' : 'vulnerabilities'}${hasFix ? ', fix available' : ''}`
    );
  }
  if (dep.compliance.licenseRisk !== 'green') {
    points.push('Licence status: ' + formatLicenseStatus(dep.compliance.license.status));
  }
  if (dep.upgrade.blocksNodeMajor) points.push('Blocks Node major upgrade');
  if (dep.upgrade.blockers?.length) {
    points.push(`${dep.upgrade.blockers.length} upgrade ${dep.upgrade.blockers.length === 1 ? 'blocker' : 'blockers'} detected`);
  }
  const executionRisk = dep.execution?.risk || 'green';
  if (executionRisk !== 'green') points.push(`${toneLabel(executionRisk)} install-time execution risk`);
  if (dep.execution?.scripts?.hooks?.length) {
    points.push(
      'Runs ' +
        dep.execution.scripts.hooks.slice(0, 2).join(', ') +
        ' lifecycle script' +
        (dep.execution.scripts.hooks.length === 1 ? '' : 's')
    );
  }
  reportAllExecutionSignals(dep)
    .slice(0, 3)
    .forEach((signal) => points.push(EXECUTION_SIGNAL_LABELS[signal]));
  if (dep.packaging?.signals?.length) {
    points.push(`${dep.packaging.signals.length} package content ${dep.packaging.signals.length === 1 ? 'signal' : 'signals'}`);
  }
  if (dep.supplyChain?.registry?.signals?.length) {
    points.push(`${dep.supplyChain.registry.signals.length} registry metadata ${dep.supplyChain.registry.signals.length === 1 ? 'signal' : 'signals'}`);
  }
  if (dep.usage.direct) {
    points.push(`Direct ${scopeLabel(dep.usage.scope).toLowerCase()} dependency`);
  } else {
    const intro = dep.usage.origins.topParentPackages?.[0]
      ? ` introduced by ${dep.usage.origins.topParentPackages[0]}`
      : '';
    points.push(`Transitive ${scopeLabel(dep.usage.scope).toLowerCase()} dependency${intro}`);
  }
  if (dep.usage.depth > 1) points.push(`Dependency depth ${dep.usage.depth}`);

  if (points.length === 0 || (vulnTotal === 0 && executionRisk === 'green' && dep.compliance.licenseRisk === 'green' && points.length < 3)) {
    [
      'No known vulnerabilities',
      'No install-time execution signals detected',
      'Licence status appears consistent',
      dep.usage.direct
        ? `Direct ${scopeLabel(dep.usage.scope).toLowerCase()} dependency`
        : `Transitive ${scopeLabel(dep.usage.scope).toLowerCase()} dependency`
    ].forEach((point) => {
      if (!points.includes(point)) points.push(point);
    });
  }

  return Array.from(new Set(points)).slice(0, 8);
}
