import { describe, expect, it } from 'vitest';
import { buildReportKeyPoints, buildReportOverallRisk, reportVulnerabilityTotal } from './reportDetailRules';
import type { DependencyRecord } from './types';

function dependency(overrides: Partial<DependencyRecord> = {}): DependencyRecord {
  const base: DependencyRecord = {
    package: {
      id: 'safe@1.0.0',
      name: 'safe',
      version: '1.0.0',
      deprecated: false,
      links: { npm: 'https://www.npmjs.com/package/safe' }
    },
    compliance: {
      license: {
        declared: { spdxId: 'MIT', expression: false, deprecated: false, valid: true },
        status: 'declared-only'
      },
      licenseRisk: 'green'
    },
    security: {
      summary: { critical: 0, high: 0, moderate: 0, low: 0, highest: 'none', risk: 'green' }
    },
    upgrade: {
      nodeEngine: null,
      outdatedStatus: 'current',
      blocksNodeMajor: false,
      blockers: []
    },
    usage: {
      direct: true,
      scope: 'runtime',
      depth: 0,
      origins: {
        rootPackageCount: 0,
        topRootPackages: [],
        parentPackageCount: 0,
        topParentPackages: []
      },
      tsTypes: 'unknown'
    },
    graph: {
      fanIn: 0,
      fanOut: 0
    }
  };
  return {
    ...base,
    ...overrides,
    package: { ...base.package, ...overrides.package },
    compliance: { ...base.compliance, ...overrides.compliance },
    security: { ...base.security, ...overrides.security },
    upgrade: { ...base.upgrade, ...overrides.upgrade },
    usage: { ...base.usage, ...overrides.usage, origins: { ...base.usage.origins, ...overrides.usage?.origins } },
    graph: { ...base.graph, ...overrides.graph }
  };
}

describe('report detail rules', () => {
  it('renders healthy fallback key points instead of an empty block', () => {
    const dep = dependency();

    expect(buildReportKeyPoints(dep, dep.security.summary)).toEqual([
      'Direct runtime dependency',
      'No known vulnerabilities',
      'No install-time execution signals detected',
      'Licence status appears consistent'
    ]);
  });

  it('prioritizes vulnerabilities, install-time signals, and upgrade blockers', () => {
    const dep = dependency({
      security: {
        summary: { critical: 0, high: 0, moderate: 1, low: 0, highest: 'moderate', risk: 'amber' },
        advisories: [
          {
            id: 'ADV-1',
            title: 'Prototype pollution',
            severity: 'moderate',
            vulnerableRange: '<2',
            fixAvailable: true,
            url: 'https://example.test/advisory'
          }
        ]
      },
      execution: {
        risk: 'red',
        scripts: {
          hooks: ['postinstall'],
          signals: ['network-access', 'reads-env', 'uses-ssh', 'child-process']
        }
      },
      upgrade: {
        nodeEngine: '<20',
        outdatedStatus: 'major',
        blocksNodeMajor: true,
        blockers: ['nodeEngine']
      },
      usage: {
        direct: false,
        scope: 'dev',
        depth: 2,
        origins: {
          rootPackageCount: 1,
          topRootPackages: [{ name: 'vite', version: '5.4.21' }],
          parentPackageCount: 1,
          topParentPackages: ['vite@5.4.21']
        },
        tsTypes: 'none'
      }
    });

    const points = buildReportKeyPoints(dep, dep.security.summary);

    expect(points).toContain('1 moderate vulnerability, fix available');
    expect(points).toContain('Blocks Node major upgrade');
    expect(points).toContain('High install-time execution risk');
    expect(points).toContain('Runs postinstall lifecycle script');
    expect(points).toContain('Accesses network during install');
    expect(points).toHaveLength(8);
  });

  it('counts known vulnerabilities deterministically', () => {
    expect(
      reportVulnerabilityTotal({
        critical: 1,
        high: 2,
        moderate: 3,
        low: 4,
        highest: 'critical',
        risk: 'red'
      })
    ).toBe(10);
  });

  it('uses the worst risk factor for overall row risk', () => {
    const dep = dependency({
      compliance: {
        license: {
          declared: { spdxId: 'MIT', expression: false, deprecated: false, valid: true },
          status: 'declared-only'
        },
        licenseRisk: 'green'
      },
      execution: {
        risk: 'red',
        scripts: { hooks: ['postinstall'] }
      }
    });

    expect(buildReportOverallRisk(dep, dep.security.summary)).toBe('red');
    expect(buildReportOverallRisk(dependency(), dependency().security.summary, 1)).toBe('amber');
  });

  it('folds every maintenance status into overall risk and key points consistently', () => {
    const withStatus = (status: 'deprecated' | 'archived' | 'unmaintained' | 'stale' | 'active') =>
      dependency({
        maintenance: { attempted: true, ok: true, status }
      });

    expect(buildReportOverallRisk(withStatus('deprecated'), dependency().security.summary)).toBe('red');
    expect(buildReportOverallRisk(withStatus('archived'), dependency().security.summary)).toBe('red');
    expect(buildReportOverallRisk(withStatus('unmaintained'), dependency().security.summary)).toBe('amber');
    // Stale is an informational cue by design: no finding, no CI rule, and no
    // risk-stripe escalation, but it must surface as a report cue.
    expect(buildReportOverallRisk(withStatus('stale'), dependency().security.summary)).toBe('green');
    expect(buildReportOverallRisk(withStatus('active'), dependency().security.summary)).toBe('green');

    const keyPointFor = (status: 'deprecated' | 'archived' | 'unmaintained' | 'stale') =>
      buildReportKeyPoints(withStatus(status), dependency().security.summary)[0];
    expect(keyPointFor('deprecated')).toBe('Deprecated by the author');
    expect(keyPointFor('archived')).toBe('Source repository is archived');
    expect(keyPointFor('unmaintained')).toBe('No registry activity for 3+ years');
    expect(keyPointFor('stale')).toBe('No registry activity for 18+ months');
  });
});
