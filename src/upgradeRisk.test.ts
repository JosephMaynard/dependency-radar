import { describe, expect, it } from 'vitest';
import { applyUpgradeRisk, deriveUpgradeRisk } from './upgradeRisk';
import type { DependencyRecord } from './types';

function dependency(upgrade: Partial<DependencyRecord['upgrade']> = {}): DependencyRecord {
  return {
    package: {
      id: 'pkg@1.0.0',
      name: 'pkg',
      version: '1.0.0',
      deprecated: false,
      links: { npm: 'https://www.npmjs.com/package/pkg' }
    },
    compliance: {
      license: { status: 'declared-only', declared: { spdxId: 'MIT', expression: false, deprecated: false, valid: true } },
      licenseRisk: 'green'
    },
    security: {
      summary: { critical: 0, high: 0, moderate: 0, low: 0, highest: 'none', risk: 'green' }
    },
    upgrade: { nodeEngine: null, ...upgrade },
    usage: {
      direct: true,
      scope: 'runtime',
      depth: 1,
      origins: { rootPackageCount: 0, topRootPackages: [], parentPackageCount: 0, topParentPackages: [] },
      tsTypes: 'unknown'
    },
    graph: { fanIn: 0, fanOut: 0 }
  };
}

describe('deriveUpgradeRisk', () => {
  it('classifies major lag, Node-major blockage, or stacked blockers as high', () => {
    expect(deriveUpgradeRisk(dependency({ outdatedStatus: 'major' }))).toBe('high');
    expect(deriveUpgradeRisk(dependency({ blocksNodeMajor: true }))).toBe('high');
    expect(deriveUpgradeRisk(dependency({ blockers: ['nativeBindings', 'deprecated'] }))).toBe('high');
  });

  it('classifies unknown outdated status as unknown', () => {
    expect(deriveUpgradeRisk(dependency({ outdatedStatus: 'unknown' }))).toBe('unknown');
  });

  it('classifies one blocker or minor lag as medium', () => {
    expect(deriveUpgradeRisk(dependency({ blockers: ['installScripts'] }))).toBe('medium');
    expect(deriveUpgradeRisk(dependency({ outdatedStatus: 'minor' }))).toBe('medium');
  });

  it('classifies current, patch, and missing data as low', () => {
    expect(deriveUpgradeRisk(dependency())).toBe('low');
    expect(deriveUpgradeRisk(dependency({ outdatedStatus: 'current' }))).toBe('low');
    expect(deriveUpgradeRisk(dependency({ outdatedStatus: 'patch' }))).toBe('low');
  });

  it('prefers high over unknown when a hard blocker coexists with unknown status', () => {
    expect(deriveUpgradeRisk(dependency({ outdatedStatus: 'unknown', blocksNodeMajor: true }))).toBe('high');
  });
});

describe('applyUpgradeRisk', () => {
  it('stamps risk on every dependency and is safe to re-run', () => {
    const outdated = dependency({ outdatedStatus: 'major' });
    const fresh = dependency();
    const aggregated = { dependencies: { 'pkg@1.0.0': outdated, 'other@1.0.0': fresh } };
    applyUpgradeRisk(aggregated);
    expect(outdated.upgrade.risk).toBe('high');
    expect(fresh.upgrade.risk).toBe('low');

    // Registry enrichment can add a blocker afterwards; re-apply picks it up.
    fresh.upgrade.blockers = ['deprecated'];
    applyUpgradeRisk(aggregated);
    expect(fresh.upgrade.risk).toBe('medium');
  });
});
