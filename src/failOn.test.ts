import { describe, expect, it } from 'vitest';
import { evaluateComparePolicyViolations, evaluatePolicyViolations, parseFailOnRules } from './failOn';
import type { AggregatedData, DependencyRecord, MaintenanceStatus, Severity } from './types';

type ExecutionScripts = NonNullable<NonNullable<DependencyRecord['execution']>['scripts']>;

function highestSeverityFromCounts(
  critical: number,
  high: number,
  moderate: number,
  low: number
): Severity | 'none' {
  if (critical > 0) return 'critical';
  if (high > 0) return 'high';
  if (moderate > 0) return 'moderate';
  if (low > 0) return 'low';
  return 'none';
}

function riskFromCounts(critical: number, high: number, moderate: number): 'green' | 'amber' | 'red' {
  if (critical > 0 || high > 0) return 'red';
  if (moderate > 0) return 'amber';
  return 'green';
}

function makeDependency(options: {
  name: string;
  version?: string;
  scope?: DependencyRecord['usage']['scope'];
  direct?: boolean;
  hasBin?: boolean;
  installHooks?: ExecutionScripts['hooks'];
  executionSignals?: NonNullable<DependencyRecord['execution']>['signals'];
  packagingSignals?: NonNullable<DependencyRecord['packaging']>['signals'];
  registrySignals?: NonNullable<NonNullable<DependencyRecord['supplyChain']>['registry']>['signals'];
  native?: boolean;
  importFileCount?: number;
  critical?: number;
  high?: number;
  moderate?: number;
  low?: number;
  licenseStatus?: DependencyRecord['compliance']['license']['status'];
  declaredSpdx?: string;
  inferredSpdx?: string;
  deprecated?: boolean;
  maintenanceStatus?: MaintenanceStatus;
}): DependencyRecord {
  const critical = options.critical ?? 0;
  const high = options.high ?? 0;
  const moderate = options.moderate ?? 0;
  const low = options.low ?? 0;

  const declared = options.declaredSpdx
    ? {
        spdxId: options.declaredSpdx,
        expression: false,
        deprecated: false,
        valid: true
      }
    : undefined;
  const inferred = options.inferredSpdx
    ? {
        spdxId: options.inferredSpdx,
        confidence: 'medium' as const
      }
    : undefined;

  const status =
    options.licenseStatus ||
    (declared && inferred
      ? 'match'
      : declared
        ? 'declared-only'
        : inferred
          ? 'inferred-only'
          : 'unknown');

  return {
    package: {
      id: `${options.name}@${options.version ?? '1.0.0'}`,
      name: options.name,
      version: options.version ?? '1.0.0',
      ...(options.hasBin ? { hasBin: true } : {}),
      deprecated: options.deprecated ?? false,
      links: {
        npm: `https://www.npmjs.com/package/${options.name}`
      }
    },
    compliance: {
      license: {
        ...(declared ? { declared } : {}),
        ...(inferred ? { inferred } : {}),
        status
      },
      licenseRisk: 'green'
    },
    security: {
      summary: {
        critical,
        high,
        moderate,
        low,
        highest: highestSeverityFromCounts(critical, high, moderate, low),
        risk: riskFromCounts(critical, high, moderate)
      }
    },
    upgrade: {
      nodeEngine: null
    },
    usage: {
      direct: options.direct ?? false,
      scope: options.scope ?? 'runtime',
      depth: 1,
      origins: {
        rootPackageCount: 0,
        topRootPackages: [],
        parentPackageCount: 0,
        topParentPackages: []
      },
      ...(options.importFileCount && options.importFileCount > 0
        ? {
            importUsage: {
              fileCount: options.importFileCount,
              topFiles: ['src/index.ts']
            }
          }
        : {}),
      tsTypes: 'unknown'
    },
    graph: {
      fanIn: 0,
      fanOut: 0
    },
    ...((options.installHooks?.length || options.native || options.executionSignals?.length)
      ? {
          execution: {
            risk: 'amber' as const,
            ...(options.native ? { native: true as const } : {}),
            ...(options.executionSignals?.length ? { signals: options.executionSignals } : {}),
            ...(options.installHooks?.length
              ? { scripts: { hooks: options.installHooks } }
              : {})
          }
        }
      : {}),
    ...(options.packagingSignals?.length
      ? { packaging: { signals: options.packagingSignals } }
      : {}),
    ...(options.registrySignals?.length
      ? {
          supplyChain: {
            registry: {
              attempted: true as const,
              ok: true,
              source: 'npm-registry' as const,
              candidateReasons: ['bin'],
              signals: options.registrySignals
            }
          }
        }
      : {}),
    ...(options.maintenanceStatus
      ? {
          maintenance: {
            attempted: true as const,
            ok: true,
            status: options.maintenanceStatus
          }
        }
      : {})
  };
}

function makeAggregatedData(dependencies: Record<string, DependencyRecord>): AggregatedData {
  const count = Object.keys(dependencies).length;
  return {
    schemaVersion: '1.6',
    generatedAt: '2026-03-01T00:00:00.000Z',
    dependencyRadarVersion: 'test',
    git: {
      branch: 'main'
    },
    project: {
      projectDir: '/tmp/project'
    },
    environment: {
      nodeVersion: 'v20.0.0',
      runtimeVersion: 'v20.0.0',
      minRequiredMajor: 20
    },
    workspaces: {
      enabled: false,
      type: 'none',
      packageCount: 1
    },
    summary: {
      dependencyCount: count,
      directCount: 0,
      transitiveCount: count
    },
    dependencies
  };
}

describe('parseFailOnRules', () => {
  it('splits comma-separated rules, trims whitespace, and deduplicates', () => {
    const rules = parseFailOnRules(' reachable-vuln, new-install-script ,reachable-vuln ');
    expect(Array.from(rules)).toEqual(['reachable-vuln', 'new-install-script']);
  });

  it('throws on unknown rules', () => {
    expect(() => parseFailOnRules('reachable-vuln,not-a-rule')).toThrow(
      'Unknown --fail-on rule: "not-a-rule"'
    );
  });

  it('throws when no rules are provided', () => {
    expect(() => parseFailOnRules(' ,  ,')).toThrow('No --fail-on rules provided.');
  });
});

describe('evaluateComparePolicyViolations', () => {
  it('detects newly introduced risky dependency traits without failing on ordinary version changes', () => {
    const previous = makeAggregatedData({
      'scripted@1.0.0': makeDependency({ name: 'scripted', version: '1.0.0' }),
      'native@1.0.0': makeDependency({ name: 'native', version: '1.0.0' }),
      'cli-bin@1.0.0': makeDependency({ name: 'cli-bin', version: '1.0.0' }),
      'direct-now@1.0.0': makeDependency({ name: 'direct-now', version: '1.0.0' }),
      'plain-bump@1.0.0': makeDependency({ name: 'plain-bump', version: '1.0.0' })
    });
    const current = makeAggregatedData({
      'scripted@1.1.0': makeDependency({ name: 'scripted', version: '1.1.0', installHooks: ['postinstall'] }),
      'native@1.1.0': makeDependency({ name: 'native', version: '1.1.0', native: true }),
      'cli-bin@1.1.0': makeDependency({ name: 'cli-bin', version: '1.1.0', hasBin: true }),
      'direct-now@1.1.0': makeDependency({ name: 'direct-now', version: '1.1.0', direct: true }),
      'plain-bump@1.1.0': makeDependency({ name: 'plain-bump', version: '1.1.0' })
    });

    const violations = evaluateComparePolicyViolations(
      previous,
      current,
      new Set(['new-install-script', 'new-native-binding', 'new-bin', 'new-direct-dependency'])
    );

    const byRule = new Map(violations.map((violation) => [violation.rule, violation]));
    expect(byRule.get('new-install-script')?.details).toEqual([
      'scripted@1.1.0 introduced install hooks: postinstall'
    ]);
    expect(byRule.get('new-native-binding')?.details).toEqual([
      'native@1.1.0 introduced native build/binary surface'
    ]);
    expect(byRule.get('new-bin')?.details).toEqual([
      'cli-bin@1.1.0 introduced a package bin'
    ]);
    expect(byRule.get('new-direct-dependency')?.details).toEqual([
      'direct-now@1.1.0 is now a direct dependency'
    ]);
    expect(violations.flatMap((violation) => violation.details || []).join('\n')).not.toContain('plain-bump');
  });

  it('detects newly deprecated dependencies against the baseline', () => {
    const previous = makeAggregatedData({
      'was-deprecated@1.0.0': makeDependency({ name: 'was-deprecated', version: '1.0.0', deprecated: true }),
      'now-deprecated@1.0.0': makeDependency({ name: 'now-deprecated', version: '1.0.0' })
    });
    const current = makeAggregatedData({
      'was-deprecated@1.1.0': makeDependency({ name: 'was-deprecated', version: '1.1.0', deprecated: true }),
      'now-deprecated@1.1.0': makeDependency({ name: 'now-deprecated', version: '1.1.0', deprecated: true })
    });

    const violations = evaluateComparePolicyViolations(previous, current, new Set(['new-deprecated']));
    expect(violations).toEqual([
      {
        rule: 'new-deprecated',
        count: 1,
        message: '1 newly deprecated dependency',
        details: ['now-deprecated@1.1.0 is now marked deprecated']
      }
    ]);
  });

  it('does not repeat trait failures when the baseline already had the same package trait', () => {
    const previous = makeAggregatedData({
      'scripted@1.0.0': makeDependency({ name: 'scripted', version: '1.0.0', installHooks: ['install'] }),
      'native@1.0.0': makeDependency({ name: 'native', version: '1.0.0', native: true }),
      'cli-bin@1.0.0': makeDependency({ name: 'cli-bin', version: '1.0.0', hasBin: true }),
      'direct@1.0.0': makeDependency({ name: 'direct', version: '1.0.0', direct: true })
    });
    const current = makeAggregatedData({
      'scripted@1.1.0': makeDependency({ name: 'scripted', version: '1.1.0', installHooks: ['postinstall'] }),
      'native@1.1.0': makeDependency({ name: 'native', version: '1.1.0', native: true }),
      'cli-bin@1.1.0': makeDependency({ name: 'cli-bin', version: '1.1.0', hasBin: true }),
      'direct@1.1.0': makeDependency({ name: 'direct', version: '1.1.0', direct: true })
    });

    expect(evaluateComparePolicyViolations(
      previous,
      current,
      new Set(['new-install-script', 'new-native-binding', 'new-bin', 'new-direct-dependency'])
    )).toEqual([]);
  });

  it('detects new supply-chain signal types per package', () => {
    const previous = makeAggregatedData({});
    previous.supplyChain = {
      signals: [
        { type: 'missing-integrity', packageName: 'already-risky', source: 'package-lock.json', detail: 'missing integrity' }
      ]
    };
    const current = makeAggregatedData({});
    current.supplyChain = {
      signals: [
        { type: 'missing-integrity', packageName: 'already-risky', packageVersion: '1.0.0', source: 'package-lock.json', detail: 'missing integrity' },
        { type: 'git-dependency', packageName: 'new-risk', packageVersion: '2.0.0', source: 'package-lock.json', detail: 'git source' }
      ]
    };

    const violations = evaluateComparePolicyViolations(
      previous,
      current,
      new Set(['new-supply-chain-signal'])
    );

    expect(violations).toEqual([
      {
        rule: 'new-supply-chain-signal',
        count: 1,
        message: '1 new supply-chain signal',
        details: ['new-risk@2.0.0 introduced supply-chain signal: git-dependency']
      }
    ]);
  });

  it('detects newly introduced execution and packaging signals', () => {
    const previous = makeAggregatedData({
      'exec@1.0.0': makeDependency({ name: 'exec', version: '1.0.0' }),
      'pkg@1.0.0': makeDependency({ name: 'pkg', version: '1.0.0' })
    });
    const current = makeAggregatedData({
      'exec@1.1.0': makeDependency({ name: 'exec', version: '1.1.0', executionSignals: ['child-process', 'reads-env'] }),
      'pkg@1.1.0': makeDependency({ name: 'pkg', version: '1.1.0', packagingSignals: ['bundled-dependencies', 'embedded-shrinkwrap'] })
    });

    const violations = evaluateComparePolicyViolations(
      previous,
      current,
      new Set(['new-child-process', 'new-env-access', 'new-bundled-dependencies', 'new-shrinkwrap'])
    );

    const byRule = new Map(violations.map((violation) => [violation.rule, violation]));
    expect(byRule.get('new-child-process')?.details).toEqual([
      'exec@1.1.0 introduced execution signal: child-process'
    ]);
    expect(byRule.get('new-env-access')?.details).toEqual([
      'exec@1.1.0 introduced execution signal: reads-env'
    ]);
    expect(byRule.get('new-bundled-dependencies')?.details).toEqual([
      'pkg@1.1.0 introduced packaging signal: bundled-dependencies'
    ]);
    expect(byRule.get('new-shrinkwrap')?.details).toEqual([
      'pkg@1.1.0 introduced packaging signal: embedded-shrinkwrap'
    ]);
  });

  it('detects newly introduced registry risk signals', () => {
    const previous = makeAggregatedData({
      'registry-risk@1.0.0': makeDependency({ name: 'registry-risk', version: '1.0.0' })
    });
    const current = makeAggregatedData({
      'registry-risk@1.0.1': makeDependency({
        name: 'registry-risk',
        version: '1.0.1',
        registrySignals: ['recent-version', 'low-release-history']
      })
    });

    const violations = evaluateComparePolicyViolations(
      previous,
      current,
      new Set(['new-recent-version', 'new-low-release-history'])
    );

    const byRule = new Map(violations.map((violation) => [violation.rule, violation]));
    expect(byRule.get('new-recent-version')?.details).toEqual([
      'registry-risk@1.0.1 introduced registry risk signal: recent-version'
    ]);
    expect(byRule.get('new-low-release-history')?.details).toEqual([
      'registry-risk@1.0.1 introduced registry risk signal: low-release-history'
    ]);
  });
});

describe('evaluatePolicyViolations', () => {
  it('only triggers directly-imported-vuln when import usage is present', () => {
    const aggregated = makeAggregatedData({
      imported: makeDependency({ name: 'imported', importFileCount: 1, high: 1 }),
      unimported: makeDependency({ name: 'unimported', high: 1 })
    });

    expect(evaluatePolicyViolations(aggregated, new Set(['directly-imported-vuln']))).toEqual([
      expect.objectContaining({ rule: 'directly-imported-vuln', count: 1 })
    ]);
  });

  it('uses reachable-vuln as the legacy rule name for directly imported vulnerabilities', () => {
    const aggregated = makeAggregatedData({
      imported: makeDependency({ name: 'imported', importFileCount: 2, moderate: 1 })
    });

    expect(evaluatePolicyViolations(aggregated, new Set(['reachable-vuln']))).toEqual([
      expect.objectContaining({ rule: 'reachable-vuln', count: 1 })
    ]);
  });

  it('returns all selected triggered rules with counts', () => {
    const aggregated = makeAggregatedData({
      'runtime-reachable-high': makeDependency({
        name: 'runtime-reachable-high',
        scope: 'runtime',
        importFileCount: 3,
        high: 1,
        licenseStatus: 'mismatch',
        declaredSpdx: 'GPL-3.0-only',
        inferredSpdx: 'MIT'
      }),
      'runtime-unreachable-moderate': makeDependency({
        name: 'runtime-unreachable-moderate',
        scope: 'runtime',
        moderate: 1
      }),
      'dev-critical': makeDependency({
        name: 'dev-critical',
        scope: 'dev',
        importFileCount: 2,
        critical: 1,
        declaredSpdx: 'AGPL-3.0-only'
      }),
      'runtime-unknown-license': makeDependency({
        name: 'runtime-unknown-license',
        scope: 'runtime'
      })
    });

    const violations = evaluatePolicyViolations(
      aggregated,
      new Set([
        'reachable-vuln',
        'production-vuln',
        'high-severity-vuln',
        'licence-mismatch',
        'copyleft-detected',
        'unknown-licence'
      ])
    );

    const byRule = new Map(violations.map((violation) => [violation.rule, violation]));
    expect(byRule.get('reachable-vuln')?.count).toBe(1);
    expect(byRule.get('production-vuln')?.count).toBe(2);
    expect(byRule.get('high-severity-vuln')?.count).toBe(2);
    expect(byRule.get('licence-mismatch')?.count).toBe(1);
    expect(byRule.get('copyleft-detected')?.count).toBe(1);
    expect(byRule.get('unknown-licence')?.count).toBe(2);
  });

  it('returns empty when selected rules are not violated', () => {
    const aggregated = makeAggregatedData({
      safe: makeDependency({
        name: 'safe',
        scope: 'runtime',
        declaredSpdx: 'MIT'
      })
    });

    const violations = evaluatePolicyViolations(
      aggregated,
      new Set(['reachable-vuln', 'unknown-licence', 'copyleft-detected'])
    );

    expect(violations).toEqual([]);
  });

  it('fails on supply-chain-source signals', () => {
    const aggregated = makeAggregatedData({});
    aggregated.supplyChain = {
      signals: [
        {
          type: 'git-dependency',
          packageName: 'git-dep',
          source: 'package-lock.json',
          detail: 'git-dep resolves from git'
        }
      ]
    };

    const violations = evaluatePolicyViolations(
      aggregated,
      new Set(['supply-chain-source'])
    );

    expect(violations).toEqual([
      {
        rule: 'supply-chain-source',
        count: 1,
        message: '1 lockfile supply-chain source finding'
      }
    ]);
  });

  it('fails on install-script supply-chain combinations, listing the pairing', () => {
    const aggregated = makeAggregatedData({
      'git-hooked@1.0.0': makeDependency({ name: 'git-hooked', installHooks: ['postinstall'] }),
      'git-plain@1.0.0': makeDependency({ name: 'git-plain' })
    });
    aggregated.supplyChain = {
      signals: [
        {
          type: 'git-dependency',
          packageName: 'git-hooked',
          source: 'package-lock.json',
          detail: 'git-hooked resolves from git'
        },
        {
          type: 'git-dependency',
          packageName: 'git-plain',
          source: 'package-lock.json',
          detail: 'git-plain resolves from git'
        }
      ]
    };

    const violations = evaluatePolicyViolations(aggregated, new Set(['supply-chain-combo']));
    expect(violations).toEqual([
      {
        rule: 'supply-chain-combo',
        count: 1,
        message: '1 install-script supply-chain combination',
        details: ['git-hooked@1.0.0: install scripts from a git-sourced package']
      }
    ]);
  });

  it('does not fire supply-chain-combo when hooks and signals never coincide', () => {
    const aggregated = makeAggregatedData({
      'hooks-only@1.0.0': makeDependency({ name: 'hooks-only', installHooks: ['postinstall'] })
    });
    aggregated.supplyChain = {
      signals: [
        {
          type: 'missing-integrity',
          packageName: 'other-pkg',
          source: 'package-lock.json',
          detail: 'other-pkg has no integrity hash'
        }
      ]
    };
    expect(evaluatePolicyViolations(aggregated, new Set(['supply-chain-combo']))).toEqual([]);
  });

  it('fails on deprecated and unmaintained dependencies', () => {
    const aggregated = makeAggregatedData({
      'deprecated-lib@1.0.0': makeDependency({ name: 'deprecated-lib', deprecated: true, maintenanceStatus: 'deprecated' }),
      'dead-lib@1.0.0': makeDependency({ name: 'dead-lib', maintenanceStatus: 'unmaintained' }),
      'archived-lib@1.0.0': makeDependency({ name: 'archived-lib', maintenanceStatus: 'archived' }),
      'stale-lib@1.0.0': makeDependency({ name: 'stale-lib', maintenanceStatus: 'stale' }),
      'fine-lib@1.0.0': makeDependency({ name: 'fine-lib', maintenanceStatus: 'active' })
    });

    const violations = evaluatePolicyViolations(
      aggregated,
      new Set(['deprecated-dependency', 'unmaintained-dependency'])
    );

    const byRule = new Map(violations.map((violation) => [violation.rule, violation]));
    expect(byRule.get('deprecated-dependency')?.count).toBe(1);
    expect(byRule.get('deprecated-dependency')?.message).toBe('1 deprecated dependency');
    // Archived counts as unmaintained; stale does not.
    expect(byRule.get('unmaintained-dependency')?.count).toBe(2);
    expect(byRule.get('unmaintained-dependency')?.message).toBe('2 unmaintained or archived dependencies');
  });
});
