import { describe, expect, it } from 'vitest';
import { evaluatePolicyViolations, parseFailOnRules } from './failOn';
import type { AggregatedData, DependencyRecord, Severity } from './types';

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
  scope?: DependencyRecord['usage']['scope'];
  importFileCount?: number;
  critical?: number;
  high?: number;
  moderate?: number;
  low?: number;
  licenseStatus?: DependencyRecord['compliance']['license']['status'];
  declaredSpdx?: string;
  inferredSpdx?: string;
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
      id: `${options.name}@1.0.0`,
      name: options.name,
      version: '1.0.0',
      deprecated: false,
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
      direct: false,
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
    }
  };
}

function makeAggregatedData(dependencies: Record<string, DependencyRecord>): AggregatedData {
  const count = Object.keys(dependencies).length;
  return {
    schemaVersion: '1.4',
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
    const rules = parseFailOnRules(' reachable-vuln, licence-mismatch ,reachable-vuln ');
    expect(Array.from(rules)).toEqual(['reachable-vuln', 'licence-mismatch']);
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

describe('evaluatePolicyViolations', () => {
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
});
