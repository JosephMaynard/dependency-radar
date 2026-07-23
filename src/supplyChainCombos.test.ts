import { describe, expect, it } from 'vitest';
import { detectSupplyChainCombos, supplyChainSignalTypesByPackageName } from './supplyChainCombos';
import type { DependencyRecord, SupplyChainSignal, SupplyChainSignalType } from './types';

function dependency(overrides: Partial<DependencyRecord> = {}): DependencyRecord {
  const base: DependencyRecord = {
    package: {
      id: 'hooked@1.0.0',
      name: 'hooked',
      version: '1.0.0',
      deprecated: false,
      links: { npm: 'https://www.npmjs.com/package/hooked' }
    },
    compliance: {
      license: { status: 'declared-only', declared: { spdxId: 'MIT', expression: false, deprecated: false, valid: true } },
      licenseRisk: 'green'
    },
    security: {
      summary: { critical: 0, high: 0, moderate: 0, low: 0, highest: 'none', risk: 'green' }
    },
    upgrade: { nodeEngine: null },
    usage: {
      direct: true,
      scope: 'runtime',
      depth: 1,
      origins: { rootPackageCount: 0, topRootPackages: [], parentPackageCount: 0, topParentPackages: [] },
      tsTypes: 'unknown'
    },
    graph: { fanIn: 0, fanOut: 0 }
  };
  return { ...base, ...overrides };
}

function withHooks(dep: DependencyRecord): DependencyRecord {
  return {
    ...dep,
    execution: { risk: 'amber', scripts: { hooks: ['postinstall'] } }
  };
}

function signal(type: SupplyChainSignalType, packageName = 'hooked'): SupplyChainSignal {
  return { type, packageName, packageVersion: '1.0.0', source: 'package-lock.json', detail: `${type} detail` };
}

describe('supplyChainSignalTypesByPackageName', () => {
  it('indexes signals by package name, deriving names from packageId when needed', () => {
    const index = supplyChainSignalTypesByPackageName([
      signal('git-dependency'),
      { type: 'missing-integrity', packageId: '@scope/pkg@2.0.0', source: 'lock', detail: 'x' },
      { type: 'non-registry-tarball', source: 'lock', detail: 'unattributed' }
    ]);
    expect(index.get('hooked')).toEqual(new Set(['git-dependency']));
    expect(index.get('@scope/pkg')).toEqual(new Set(['missing-integrity']));
    expect(index.size).toBe(2);
  });

  it('returns an empty index for missing input', () => {
    expect(supplyChainSignalTypesByPackageName(undefined).size).toBe(0);
  });
});

describe('detectSupplyChainCombos', () => {
  it('returns nothing without install hooks', () => {
    const combos = detectSupplyChainCombos(dependency(), new Set(['git-dependency']));
    expect(combos).toEqual([]);
  });

  it('returns nothing when hooks exist but no source signals do', () => {
    expect(detectSupplyChainCombos(withHooks(dependency()), undefined)).toEqual([]);
    expect(detectSupplyChainCombos(withHooks(dependency()), new Set())).toEqual([]);
  });

  it('flags install hooks combined with mutable or unverifiable sources', () => {
    const combos = detectSupplyChainCombos(
      withHooks(dependency()),
      new Set(['git-dependency', 'missing-integrity'])
    );
    expect(combos.map((combo) => [combo.type, combo.severity])).toEqual([
      ['install-scripts-git-source', 'error'],
      ['install-scripts-missing-integrity', 'warning']
    ]);
    expect(combos[0].hooks).toEqual(['postinstall']);
  });

  it('treats non-registry tarballs and unexpected hosts as error severity', () => {
    const combos = detectSupplyChainCombos(
      withHooks(dependency()),
      new Set(['non-registry-tarball', 'unexpected-registry-host'])
    );
    expect(combos.every((combo) => combo.severity === 'error')).toBe(true);
    expect(combos).toHaveLength(2);
  });

  it('ignores file-dependency signals (no combo rule)', () => {
    const combos = detectSupplyChainCombos(withHooks(dependency()), new Set(['file-dependency']));
    expect(combos).toEqual([]);
  });
});
