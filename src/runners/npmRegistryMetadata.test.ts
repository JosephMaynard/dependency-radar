import { describe, expect, it } from 'vitest';
import {
  deriveRegistryRiskSignals,
  enrichAggregatedWithRegistryMetadata,
  parseNpmRegistryMetadata,
  selectRegistryEnrichmentCandidates
} from './npmRegistryMetadata';
import type { AggregatedData, DependencyRecord } from '../types';

function makeDependency(options: {
  name: string;
  version?: string;
  hasBin?: boolean;
  installHooks?: boolean;
  native?: boolean;
  executionSignals?: NonNullable<DependencyRecord['execution']>['signals'];
  packagingSignals?: NonNullable<DependencyRecord['packaging']>['signals'];
}): DependencyRecord {
  const version = options.version || '1.0.0';
  return {
    package: {
      id: `${options.name}@${version}`,
      name: options.name,
      version,
      ...(options.hasBin ? { hasBin: true as const } : {}),
      deprecated: false,
      links: { npm: `https://www.npmjs.com/package/${options.name}` }
    },
    compliance: { license: { status: 'declared-only' }, licenseRisk: 'green' },
    security: { summary: { critical: 0, high: 0, moderate: 0, low: 0, highest: 'none', risk: 'green' } },
    upgrade: { nodeEngine: null },
    usage: {
      direct: false,
      scope: 'runtime',
      depth: 1,
      origins: { rootPackageCount: 0, topRootPackages: [], parentPackageCount: 0, topParentPackages: [] },
      tsTypes: 'unknown'
    },
    graph: { fanIn: 0, fanOut: 0 },
    ...((options.installHooks || options.native || options.executionSignals?.length)
      ? {
          execution: {
            risk: 'amber' as const,
            ...(options.native ? { native: true as const } : {}),
            ...(options.executionSignals?.length ? { signals: options.executionSignals } : {}),
            ...(options.installHooks ? { scripts: { hooks: ['postinstall' as const] } } : {})
          }
        }
      : {}),
    ...(options.packagingSignals?.length ? { packaging: { signals: options.packagingSignals } } : {})
  };
}

function makeAggregated(dependencies: Record<string, DependencyRecord>): AggregatedData {
  const count = Object.keys(dependencies).length;
  return {
    schemaVersion: '1.6',
    generatedAt: '2026-05-01T00:00:00.000Z',
    dependencyRadarVersion: 'test',
    git: { branch: 'main' },
    project: { projectDir: '/tmp/project' },
    environment: { nodeVersion: 'v20.0.0', runtimeVersion: 'v20.0.0', minRequiredMajor: 20 },
    workspaces: { enabled: false, type: 'none', packageCount: 1 },
    summary: { dependencyCount: count, directCount: 0, transitiveCount: count },
    dependencies
  };
}

describe('npm registry metadata enrichment', () => {
  it('selects only suspicious packages and applies the lookup cap', () => {
    const aggregated = makeAggregated({
      'safe@1.0.0': makeDependency({ name: 'safe' }),
      'with-bin@1.0.0': makeDependency({ name: 'with-bin', hasBin: true }),
      'with-script@1.0.0': makeDependency({ name: 'with-script', installHooks: true }),
      'with-packaging@1.0.0': makeDependency({ name: 'with-packaging', packagingSignals: ['bundled-dependencies'] })
    });

    expect(selectRegistryEnrichmentCandidates(aggregated, 2)).toEqual([
      { name: 'with-script', reasons: ['install-hooks'] },
      { name: 'with-packaging', reasons: ['packaging-signals'] }
    ]);
  });

  it('parses npm metadata and derives conservative registry signals', () => {
    const metadata = parseNpmRegistryMetadata('risky', {
      time: {
        created: '2026-05-01T00:00:00.000Z',
        modified: '2026-05-10T00:00:00.000Z',
        '1.0.0': '2024-01-01T00:00:00.000Z',
        '1.0.1': '2026-05-10T00:00:00.000Z',
        '2.0.0': '2025-01-01T00:00:00.000Z'
      },
      'dist-tags': { latest: '2.0.0' },
      versions: ['1.0.0', '1.0.1', '2.0.0']
    });

    expect(metadata?.versions).toEqual(['1.0.0', '1.0.1', '2.0.0']);
    expect(deriveRegistryRiskSignals('1.0.1', metadata!, new Date('2026-05-12T00:00:00.000Z'))).toEqual([
      'recent-package',
      'recent-version',
      'low-release-history',
      'reactivated-package',
      'old-major-new-patch'
    ]);
  });

  it('skips enrichment when offline', async () => {
    const aggregated = makeAggregated({
      'with-bin@1.0.0': makeDependency({ name: 'with-bin', hasBin: true })
    });

    const result = await enrichAggregatedWithRegistryMetadata(aggregated, {
      offline: true,
      fetcher: async () => {
        throw new Error('should not fetch');
      }
    });

    expect(result).toEqual({ candidates: [], attempted: 0, succeeded: 0 });
    expect(aggregated.dependencies['with-bin@1.0.0'].supplyChain?.registry).toBeUndefined();
  });

  it('attaches registry enrichment to suspicious package records', async () => {
    const aggregated = makeAggregated({
      'with-bin@1.0.0': makeDependency({ name: 'with-bin', hasBin: true })
    });

    const result = await enrichAggregatedWithRegistryMetadata(aggregated, {
      now: new Date('2026-05-12T00:00:00.000Z'),
      fetcher: async (name) => ({
        ok: true,
        data: {
          name,
          time: {
            created: '2026-05-01T00:00:00.000Z',
            modified: '2026-05-02T00:00:00.000Z',
            '1.0.0': '2026-05-02T00:00:00.000Z'
          },
          distTags: { latest: '1.0.0' },
          versions: ['1.0.0']
        }
      })
    });

    expect(result.attempted).toBe(1);
    expect(aggregated.dependencies['with-bin@1.0.0'].supplyChain?.registry).toEqual(
      expect.objectContaining({
        attempted: true,
        ok: true,
        candidateReasons: ['bin'],
        versionCount: 1,
        signals: ['recent-package', 'recent-version', 'low-release-history']
      })
    );
  });
});
