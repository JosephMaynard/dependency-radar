import { describe, expect, it } from 'vitest';
import { buildWorkspaceFilterOptions } from './workspaceFilter';
import type { AggregatedData, DependencyRecord } from './types';

function dependency(name: string, workspaces: string[]): DependencyRecord {
  return {
    package: {
      id: `${name}@1.0.0`,
      name,
      version: '1.0.0',
      deprecated: false,
      links: {}
    },
    compliance: {
      license: { status: 'unknown' },
      licenseRisk: 'green'
    },
    security: {
      summary: {
        critical: 0,
        high: 0,
        moderate: 0,
        low: 0,
        highest: 'none',
        risk: 'green'
      }
    },
    upgrade: { nodeEngine: null },
    usage: {
      direct: true,
      scope: 'runtime',
      depth: 0,
      origins: {
        rootPackageCount: 1,
        topRootPackages: [name],
        parentPackageCount: 0,
        topParentPackages: [],
        workspaces
      },
      tsTypes: 'unknown'
    },
    graph: {
      fanIn: 0,
      fanOut: 0
    }
  };
}

function report(options: {
  enabled: boolean;
  workspacePackages?: string[];
  dependencyWorkspaces?: Record<string, string[]>;
}): Pick<AggregatedData, 'workspaces' | 'dependencies'> {
  return {
    workspaces: {
      enabled: options.enabled,
      type: options.enabled ? 'npm' : 'none',
      packageCount: options.workspacePackages?.length || 1,
      workspacePackages: options.workspacePackages?.map((name) => ({ name, path: `packages/${name}` }))
    },
    dependencies: Object.fromEntries(
      Object.entries(options.dependencyWorkspaces || {}).map(([name, workspaces]) => [
        `${name}@1.0.0`,
        dependency(name, workspaces)
      ])
    )
  };
}

describe('buildWorkspaceFilterOptions', () => {
  it('hides the workspace dropdown for non-workspace reports', () => {
    expect(buildWorkspaceFilterOptions(report({
      enabled: false,
      workspacePackages: ['root', 'packages/api'],
      dependencyWorkspaces: {
        react: ['packages/web']
      }
    }))).toEqual([]);
  });

  it('uses graph-view workspace semantics with root first and stable ordering', () => {
    expect(buildWorkspaceFilterOptions(report({
      enabled: true,
      workspacePackages: ['packages/web', 'root'],
      dependencyWorkspaces: {
        react: ['packages/web', 'packages/api'],
        typescript: ['root'],
        eslint: ['packages/api']
      }
    }))).toEqual(['root', 'packages/api', 'packages/web']);
  });
});
