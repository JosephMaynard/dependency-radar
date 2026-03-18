import { describe, expect, it } from 'vitest';
import type { AggregatedData, DependencyRecord } from './types';
import {
  findDependenciesByPackageName,
  formatExplainOutput,
} from './explain';

function makeDependency(
  overrides: Partial<DependencyRecord> & {
    name: string;
    version: string;
  },
): DependencyRecord {
  return {
    package: {
      id: `${overrides.name}@${overrides.version}`,
      name: overrides.name,
      version: overrides.version,
      deprecated: false,
      links: {
        npm: `https://www.npmjs.com/package/${overrides.name}`,
      },
      ...(overrides.package || {}),
    },
    compliance: {
      license: {
        status: 'match',
        declared: {
          spdxId: 'MIT',
          expression: false,
          deprecated: false,
          valid: true,
        },
      },
      licenseRisk: 'green',
      ...(overrides.compliance || {}),
    },
    security: {
      summary: {
        critical: 0,
        high: 0,
        moderate: 0,
        low: 0,
        highest: 'none',
        risk: 'green',
      },
      ...(overrides.security || {}),
    },
    upgrade: {
      nodeEngine: null,
      ...(overrides.upgrade || {}),
    },
    usage: {
      direct: false,
      scope: 'runtime',
      depth: 2,
      origins: {
        rootPackageCount: 1,
        topRootPackages: [{ name: 'app-shell', version: '1.0.0' }],
        parentPackageCount: 1,
        topParentPackages: ['utility-lib@2.0.0'],
      },
      introduction: 'transitive',
      runtimeImpact: 'runtime',
      importUsage: {
        fileCount: 2,
        topFiles: ['src/index.ts', 'src/server.ts'],
      },
      tsTypes: 'none',
      ...(overrides.usage || {}),
    },
    graph: {
      fanIn: 1,
      fanOut: 0,
      ...(overrides.graph || {}),
    },
    ...(overrides.execution ? { execution: overrides.execution } : {}),
  };
}

describe('explain helpers', () => {
  it('filters dependencies by exact package name', () => {
    const aggregated = {
      dependencies: {
        'lodash@4.17.21': makeDependency({ name: 'lodash', version: '4.17.21' }),
        'lodash-es@4.17.21': makeDependency({
          name: 'lodash-es',
          version: '4.17.21',
        }),
      },
    } as AggregatedData;

    const matches = findDependenciesByPackageName(aggregated, 'lodash');
    expect(matches).toHaveLength(1);
    expect(matches[0].package.id).toBe('lodash@4.17.21');
  });

  it('formats multiple versions and uses existing model fields', () => {
    const aggregated = {
      dependencies: {
        'lodash@4.17.21': makeDependency({
          name: 'lodash',
          version: '4.17.21',
          security: {
            summary: {
              critical: 0,
              high: 1,
              moderate: 0,
              low: 0,
              highest: 'high',
              risk: 'red',
            },
          },
          upgrade: {
            nodeEngine: '<18',
            blockers: ['nodeEngine'],
          },
        }),
        'lodash@4.17.15': makeDependency({
          name: 'lodash',
          version: '4.17.15',
          usage: {
            direct: false,
            scope: 'dev',
            depth: 3,
            origins: {
              rootPackageCount: 1,
              topRootPackages: [{ name: 'vitest', version: '1.0.0' }],
              parentPackageCount: 1,
              topParentPackages: ['test-runner@1.0.0'],
            },
            introduction: 'tooling',
            runtimeImpact: 'tooling',
            tsTypes: 'none',
          },
        }),
      },
    } as AggregatedData;

    const matches = findDependenciesByPackageName(aggregated, 'lodash');
    const output = formatExplainOutput('lodash', matches, {
      audit: 'available',
      importGraphComplete: true,
    });

    expect(output).toContain('lodash (2 versions detected)');
    expect(output).toContain('lodash@4.17.21');
    expect(output).toContain('lodash@4.17.15');
    expect(output).toContain('Vulnerabilities:\n  1 advisory (highest severity: high)');
    expect(output).toContain('Other detected versions:\n  4.17.15');
    expect(output).toContain('Upgrade blockers:\n  - Node engine constraint');
  });

  it('marks audit data as unavailable when explain runs offline', () => {
    const dep = makeDependency({
      name: 'left-pad',
      version: '1.3.0',
      usage: {
        direct: true,
        scope: 'runtime',
        depth: 1,
        origins: {
          rootPackageCount: 1,
          topRootPackages: [{ name: 'left-pad', version: '1.3.0' }],
          parentPackageCount: 0,
          topParentPackages: [],
        },
        introduction: 'direct',
        runtimeImpact: undefined,
        importUsage: undefined,
        tsTypes: 'none',
      },
    });
    const output = formatExplainOutput('left-pad', [dep], {
      audit: 'skipped',
      importGraphComplete: false,
    });

    expect(output).toContain('Static import evidence: unknown');
    expect(output).toContain('Imported in:\n  unavailable (import graph incomplete)');
    expect(output).toContain('Vulnerabilities:\n  not available (--offline)');
  });
});
