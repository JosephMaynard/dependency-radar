import { describe, expect, it } from 'vitest';
import { buildDependencyFindings } from './findings';
import type { DependencyMaintenanceInfo, DependencyRecord } from './types';

function makeDependency(options: {
  name: string;
  deprecated?: boolean;
  scope?: DependencyRecord['usage']['scope'];
  maintenance?: DependencyMaintenanceInfo;
}): DependencyRecord {
  return {
    package: {
      id: `${options.name}@1.0.0`,
      name: options.name,
      version: '1.0.0',
      deprecated: options.deprecated ?? false,
      links: { npm: `https://www.npmjs.com/package/${options.name}` }
    },
    compliance: { license: { status: 'declared-only' }, licenseRisk: 'green' },
    security: { summary: { critical: 0, high: 0, moderate: 0, low: 0, highest: 'none', risk: 'green' } },
    upgrade: { nodeEngine: null },
    usage: {
      direct: true,
      scope: options.scope ?? 'runtime',
      depth: 1,
      origins: { rootPackageCount: 0, topRootPackages: [], parentPackageCount: 0, topParentPackages: [] },
      tsTypes: 'unknown'
    },
    graph: { fanIn: 0, fanOut: 0 },
    ...(options.maintenance ? { maintenance: options.maintenance } : {})
  };
}

describe('buildDependencyFindings supply-chain signals', () => {
  it('normalizes lockfile source-risk signals into dependency findings', () => {
    const findings = buildDependencyFindings({
      dependencies: {},
      supplyChain: {
        ok: true,
        signals: [
          {
            type: 'git-dependency',
            packageName: 'git-dep',
            packageVersion: '1.0.0',
            packageId: 'git-dep@1.0.0',
            source: 'package-lock.json',
            detail: 'git-dep@1.0.0 resolves from git+https://github.com/example/git-dep.git'
          }
        ]
      }
    });

    expect(findings).toMatchObject([
      {
        category: 'supply-chain',
        severity: 'info',
        packageId: 'git-dep@1.0.0',
        title: 'Git dependency source'
      }
    ]);
  });

  it('adds a finding when npm signature/provenance verification fails', () => {
    const findings = buildDependencyFindings({
      dependencies: {},
      supplyChain: {
        ok: false,
        signals: [],
        signatureAudit: {
          attempted: true,
          ok: false,
          error: 'registry signature check failed',
          output: 'npm audit signatures output'
        }
      }
    });

    expect(findings).toMatchObject([
      {
        id: 'supply-chain:signature-verification-failed',
        category: 'supply-chain',
        severity: 'warning',
        title: 'npm signature/provenance verification failed',
        evidence: 'npm audit signatures output'
      }
    ]);
  });
});

describe('buildDependencyFindings maintenance signals', () => {
  it('cites the registry deprecation message when maintenance data is present', () => {
    const findings = buildDependencyFindings({
      dependencies: {
        'old-lib@1.0.0': makeDependency({
          name: 'old-lib',
          deprecated: true,
          maintenance: {
            attempted: true,
            ok: true,
            status: 'deprecated',
            deprecated: { installedVersion: true, latestVersion: false, message: 'use new-lib instead' }
          }
        })
      }
    });

    expect(findings).toMatchObject([
      {
        category: 'supply-chain',
        severity: 'warning',
        title: 'Package is deprecated',
        message: 'old-lib@1.0.0 is marked deprecated on the npm registry.',
        evidence: 'use new-lib instead'
      }
    ]);
  });

  it('keeps the local-metadata wording without maintenance data', () => {
    const findings = buildDependencyFindings({
      dependencies: {
        'old-lib@1.0.0': makeDependency({ name: 'old-lib', deprecated: true })
      }
    });

    expect(findings).toMatchObject([
      { title: 'Package is deprecated', message: 'old-lib@1.0.0 is marked deprecated in local package metadata.' }
    ]);
  });

  it('adds archived and unmaintained findings with scope-aware severities', () => {
    const findings = buildDependencyFindings({
      dependencies: {
        'archived-lib@1.0.0': makeDependency({
          name: 'archived-lib',
          maintenance: { attempted: true, ok: true, status: 'archived', repoArchived: true, repoCheckedAt: '2026-07-01T00:00:00.000Z' }
        }),
        'dead-lib@1.0.0': makeDependency({
          name: 'dead-lib',
          scope: 'dev',
          maintenance: {
            attempted: true,
            ok: true,
            status: 'unmaintained',
            monthsSinceModified: 40,
            packageModifiedAt: '2023-02-01T00:00:00.000Z'
          }
        }),
        'unknown-age-lib@1.0.0': makeDependency({
          name: 'unknown-age-lib',
          maintenance: {
            attempted: true,
            ok: true,
            status: 'unmaintained'
          }
        }),
        'stale-lib@1.0.0': makeDependency({
          name: 'stale-lib',
          maintenance: { attempted: true, ok: true, status: 'stale', monthsSinceModified: 20 }
        })
      }
    });

    expect(findings).toMatchObject([
      {
        id: 'archived-lib@1.0.0-maintenance-archived',
        severity: 'warning',
        title: 'Source repository is archived'
      },
      {
        id: 'dead-lib@1.0.0-maintenance-unmaintained',
        severity: 'info',
        title: 'Package looks unmaintained',
        message: 'dead-lib@1.0.0 has had no npm registry activity for 40 months.'
      },
      {
        id: 'unknown-age-lib@1.0.0-maintenance-unmaintained',
        severity: 'info',
        title: 'Package looks unmaintained',
        message: 'unknown-age-lib@1.0.0 has had no recent npm registry activity.'
      }
    ]);
    // Stale produces no finding by design.
    expect(findings.some((finding) => finding.packageId === 'stale-lib@1.0.0')).toBe(false);
  });

  it('produces no finding for the slowing tier', () => {
    const findings = buildDependencyFindings({
      dependencies: {
        'quiet-lib@1.0.0': makeDependency({
          name: 'quiet-lib',
          maintenance: { attempted: true, ok: true, status: 'slowing', monthsSinceModified: 14 }
        })
      }
    });
    expect(findings).toEqual([]);
  });
});

describe('buildDependencyFindings supply-chain combos', () => {
  it('escalates install hooks combined with a git source into an error finding', () => {
    const dep = makeDependency({ name: 'git-dep' });
    dep.execution = { risk: 'amber', scripts: { hooks: ['postinstall'] } };
    const findings = buildDependencyFindings({
      dependencies: { 'git-dep@1.0.0': dep },
      supplyChain: {
        ok: true,
        signals: [
          {
            type: 'git-dependency',
            packageName: 'git-dep',
            packageVersion: '1.0.0',
            packageId: 'git-dep@1.0.0',
            source: 'package-lock.json',
            detail: 'git-dep@1.0.0 resolves from git+https://github.com/example/git-dep.git'
          }
        ]
      }
    });

    const combo = findings.find((finding) => finding.id.includes('install-scripts-git-source'));
    expect(combo).toMatchObject({
      category: 'supply-chain',
      severity: 'error',
      packageId: 'git-dep@1.0.0',
      title: 'Install scripts from a git-sourced package',
      evidence: 'hooks=postinstall; signal=git-dependency'
    });
  });

  it('does not create combo findings when hooks or source signals are absent', () => {
    const hooksOnly = makeDependency({ name: 'hooks-only' });
    hooksOnly.execution = { risk: 'amber', scripts: { hooks: ['postinstall'] } };
    const signalOnly = makeDependency({ name: 'signal-only' });
    const findings = buildDependencyFindings({
      dependencies: { 'hooks-only@1.0.0': hooksOnly, 'signal-only@1.0.0': signalOnly },
      supplyChain: {
        ok: true,
        signals: [
          {
            type: 'git-dependency',
            packageName: 'signal-only',
            packageVersion: '1.0.0',
            packageId: 'signal-only@1.0.0',
            source: 'package-lock.json',
            detail: 'signal-only@1.0.0 resolves from git'
          }
        ]
      }
    });
    expect(findings.some((finding) => finding.id.includes('install-scripts-'))).toBe(false);
  });
});

describe('buildDependencyFindings replacement suggestions', () => {
  const replacement = {
    source: 'e18e-module-replacements' as const,
    manifest: 'preferred' as const,
    type: 'documented' as const,
    replacements: ['tinyexec'],
    docUrl: 'https://e18e.dev/docs/replacements/execa'
  };

  it('adds an info modernization finding for direct dependencies', () => {
    const dep = makeDependency({ name: 'execa' });
    dep.replacement = replacement;
    const findings = buildDependencyFindings({ dependencies: { 'execa@1.0.0': dep } });
    expect(findings).toMatchObject([
      {
        category: 'modernization',
        severity: 'info',
        title: 'Community-suggested replacement available',
        message: 'execa@1.0.0 could be replaced by a lighter alternative: tinyexec.',
        evidence: 'https://e18e.dev/docs/replacements/execa'
      }
    ]);
  });

  it('stays silent for transitive dependencies', () => {
    const dep = makeDependency({ name: 'execa' });
    dep.usage.direct = false;
    dep.replacement = replacement;
    const findings = buildDependencyFindings({ dependencies: { 'execa@1.0.0': dep } });
    expect(findings).toEqual([]);
  });
});
