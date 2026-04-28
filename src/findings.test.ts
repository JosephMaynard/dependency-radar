import { describe, expect, it } from 'vitest';
import { buildDependencyFindings } from './findings';

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
