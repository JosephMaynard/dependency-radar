import http from 'http';
import { AddressInfo } from 'net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  deriveMaintenanceStatus,
  enrichAggregatedWithMaintenanceSignals,
  parseAbbreviatedPackument,
  parseGitHubRepo,
  selectArchivedCheckCandidates
} from './maintenanceSignals';
import { MaintenanceCache } from '../maintenanceCache';
import type { AggregatedData, DependencyRecord } from '../types';
import type { HttpJsonResult } from '../httpClient';

const NOW = new Date('2026-07-01T00:00:00.000Z');

afterEach(() => {
  vi.restoreAllMocks();
});

function monthsAgo(months: number): string {
  return new Date(NOW.getTime() - months * 30.44 * 24 * 60 * 60 * 1000).toISOString();
}

function makeDependency(options: {
  name: string;
  version?: string;
  direct?: boolean;
  repository?: string;
  latestVersion?: string;
  blockers?: NonNullable<DependencyRecord['upgrade']['blockers']>;
}): DependencyRecord {
  const version = options.version || '1.0.0';
  return {
    package: {
      id: `${options.name}@${version}`,
      name: options.name,
      version,
      deprecated: false,
      links: {
        npm: `https://www.npmjs.com/package/${options.name}`,
        ...(options.repository ? { repository: options.repository } : {})
      }
    },
    compliance: { license: { status: 'declared-only' }, licenseRisk: 'green' },
    security: { summary: { critical: 0, high: 0, moderate: 0, low: 0, highest: 'none', risk: 'green' } },
    upgrade: {
      nodeEngine: null,
      ...(options.latestVersion ? { latestVersion: options.latestVersion } : {}),
      ...(options.blockers ? { blockers: [...options.blockers] } : {})
    },
    usage: {
      direct: Boolean(options.direct),
      scope: 'runtime',
      depth: 1,
      origins: { rootPackageCount: 0, topRootPackages: [], parentPackageCount: 0, topParentPackages: [] },
      tsTypes: 'unknown'
    },
    graph: { fanIn: 0, fanOut: 0 }
  };
}

function makeAggregated(dependencies: Record<string, DependencyRecord>): AggregatedData {
  const count = Object.keys(dependencies).length;
  return {
    schemaVersion: '1.6',
    generatedAt: NOW.toISOString(),
    dependencyRadarVersion: 'test',
    git: { branch: 'main' },
    project: { projectDir: '/tmp/project' },
    environment: { nodeVersion: 'v20.0.0', runtimeVersion: 'v20.0.0', minRequiredMajor: 20 },
    workspaces: { enabled: false, type: 'none', packageCount: 1 },
    summary: { dependencyCount: count, directCount: 0, transitiveCount: count },
    dependencies
  };
}

function packument(options: {
  modified?: string;
  latest?: string;
  deprecated?: Record<string, string | boolean>;
}): HttpJsonResult {
  const versions: Record<string, any> = {};
  for (const [version, message] of Object.entries(options.deprecated || {})) {
    versions[version] = { deprecated: message };
  }
  if (options.latest && !versions[options.latest]) versions[options.latest] = {};
  return {
    ok: true,
    status: 200,
    data: {
      modified: options.modified,
      'dist-tags': options.latest ? { latest: options.latest } : {},
      versions
    }
  };
}

describe('parseAbbreviatedPackument', () => {
  it('extracts modified, latest, and truthy deprecations with capped messages', () => {
    const entry = parseAbbreviatedPackument(
      {
        modified: '2020-01-01T00:00:00.000Z',
        'dist-tags': { latest: '2.0.0' },
        versions: {
          '1.0.0': { deprecated: 'x'.repeat(500) },
          '1.5.0': { deprecated: false },
          '1.6.0': { deprecated: '' },
          '2.0.0': { deprecated: true }
        }
      },
      NOW
    );

    expect(entry?.modified).toBe('2020-01-01T00:00:00.000Z');
    expect(entry?.latestVersion).toBe('2.0.0');
    expect(entry?.deprecatedVersions?.['1.0.0']).toHaveLength(300);
    expect(entry?.deprecatedVersions?.['1.5.0']).toBeUndefined();
    expect(entry?.deprecatedVersions?.['1.6.0']).toBeUndefined();
    expect(entry?.deprecatedVersions?.['2.0.0']).toBe('deprecated');
    expect(entry?.latestDeprecated).toBe(true);
  });

  it('returns undefined for unusable payloads', () => {
    expect(parseAbbreviatedPackument(undefined, NOW)).toBeUndefined();
    expect(parseAbbreviatedPackument('nope', NOW)).toBeUndefined();
    expect(parseAbbreviatedPackument({ error: 'Not found' }, NOW)).toBeUndefined();
  });
});

describe('deriveMaintenanceStatus', () => {
  it('applies the documented precedence and single-signal thresholds', () => {
    expect(deriveMaintenanceStatus({ deprecated: true, repoArchived: true })).toBe('deprecated');
    expect(deriveMaintenanceStatus({ deprecated: false, repoArchived: true, monthsSinceModified: 40 })).toBe('archived');
    expect(deriveMaintenanceStatus({ deprecated: false, monthsSinceModified: 11 })).toBe('active');
    expect(deriveMaintenanceStatus({ deprecated: false, monthsSinceModified: 17 })).toBe('slowing');
    expect(deriveMaintenanceStatus({ deprecated: false, monthsSinceModified: 19 })).toBe('stale');
    expect(deriveMaintenanceStatus({ deprecated: false, monthsSinceModified: 35 })).toBe('stale');
    expect(deriveMaintenanceStatus({ deprecated: false, monthsSinceModified: 37 })).toBe('unmaintained');
    expect(deriveMaintenanceStatus({ deprecated: false })).toBe('active');
  });

  it('requires both surfaces to be quiet before escalating when repo push data exists', () => {
    // Registry quiet for 3+ years but the repo is actively pushed: slowing, not unmaintained.
    expect(
      deriveMaintenanceStatus({ deprecated: false, monthsSinceModified: 40, monthsSinceRepoPush: 2 })
    ).toBe('slowing');
    // Both quiet long enough for the dual unmaintained tier (24/12).
    expect(
      deriveMaintenanceStatus({ deprecated: false, monthsSinceModified: 25, monthsSinceRepoPush: 13 })
    ).toBe('unmaintained');
    // Both moderately quiet (12/6) -> stale.
    expect(
      deriveMaintenanceStatus({ deprecated: false, monthsSinceModified: 13, monthsSinceRepoPush: 7 })
    ).toBe('stale');
    // Registry quiet but repo pushed recently -> slowing.
    expect(
      deriveMaintenanceStatus({ deprecated: false, monthsSinceModified: 13, monthsSinceRepoPush: 1 })
    ).toBe('slowing');
    // Registry active -> active regardless of repo cadence.
    expect(
      deriveMaintenanceStatus({ deprecated: false, monthsSinceModified: 3, monthsSinceRepoPush: 20 })
    ).toBe('active');
  });
});

describe('parseGitHubRepo', () => {
  it('parses common repository URL forms', () => {
    expect(parseGitHubRepo('https://github.com/owner/repo')).toEqual({ owner: 'owner', repo: 'repo' });
    expect(parseGitHubRepo('git+https://github.com/owner/repo.git')).toEqual({ owner: 'owner', repo: 'repo' });
    expect(parseGitHubRepo('git@github.com:owner/repo.git')).toEqual({ owner: 'owner', repo: 'repo' });
    expect(parseGitHubRepo('ssh://git@github.com/owner/repo.git')).toEqual({ owner: 'owner', repo: 'repo' });
    expect(parseGitHubRepo('git://github.com/owner/repo.git')).toEqual({ owner: 'owner', repo: 'repo' });
    expect(parseGitHubRepo('https://github.com/owner/repo/tree/main/packages/x')).toEqual({
      owner: 'owner',
      repo: 'repo'
    });
  });

  it('rejects non-GitHub and malformed URLs', () => {
    expect(parseGitHubRepo('https://gitlab.com/owner/repo')).toBeUndefined();
    expect(parseGitHubRepo('not a url')).toBeUndefined();
    expect(parseGitHubRepo(undefined)).toBeUndefined();
  });
});

describe('enrichAggregatedWithMaintenanceSignals', () => {
  it('is a no-op when offline', async () => {
    const aggregated = makeAggregated({ 'lib@1.0.0': makeDependency({ name: 'lib' }) });
    const summary = await enrichAggregatedWithMaintenanceSignals(aggregated, {
      offline: true,
      fetcher: async () => {
        throw new Error('should not fetch');
      }
    });

    expect(summary.checkedNames).toBe(0);
    expect(aggregated.dependencies['lib@1.0.0'].maintenance).toBeUndefined();
  });

  it('marks registry-deprecated installed versions and promotes package.deprecated + blocker', async () => {
    const aggregated = makeAggregated({
      'old-lib@1.0.0': makeDependency({ name: 'old-lib', blockers: ['deprecated'] })
    });

    const summary = await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache: new MaintenanceCache(undefined),
      fetcher: async () =>
        packument({
          modified: monthsAgo(2),
          latest: '2.0.0',
          deprecated: { '1.0.0': 'use new-lib instead' }
        })
    });

    const dep = aggregated.dependencies['old-lib@1.0.0'];
    expect(dep.maintenance?.status).toBe('deprecated');
    expect(dep.maintenance?.deprecated).toEqual({
      installedVersion: true,
      latestVersion: false,
      message: 'use new-lib instead'
    });
    expect(dep.package.deprecated).toBe(true);
    // Idempotent: the pre-existing blocker is not duplicated.
    expect(dep.upgrade.blockers).toEqual(['deprecated']);
    expect(summary.deprecatedNames).toBe(1);
  });

  it('treats a deprecated latest version as deprecation even when the installed version is not', async () => {
    const aggregated = makeAggregated({ 'lib@1.0.0': makeDependency({ name: 'lib' }) });

    await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache: new MaintenanceCache(undefined),
      fetcher: async () =>
        packument({ modified: monthsAgo(1), latest: '2.0.0', deprecated: { '2.0.0': 'abandoned' } })
    });

    const dep = aggregated.dependencies['lib@1.0.0'];
    expect(dep.maintenance?.status).toBe('deprecated');
    expect(dep.maintenance?.deprecated).toEqual({
      installedVersion: false,
      latestVersion: true,
      message: 'abandoned'
    });
  });

  it('derives stale and unmaintained statuses from registry inactivity', async () => {
    const aggregated = makeAggregated({
      'stale-lib@1.0.0': makeDependency({ name: 'stale-lib' }),
      'dead-lib@1.0.0': makeDependency({ name: 'dead-lib' }),
      'fresh-lib@1.0.0': makeDependency({ name: 'fresh-lib' })
    });
    const modifiedByName: Record<string, string> = {
      'stale-lib': monthsAgo(19),
      'dead-lib': monthsAgo(37),
      'fresh-lib': monthsAgo(1)
    };

    const summary = await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache: new MaintenanceCache(undefined),
      fetcher: async (name) => packument({ modified: modifiedByName[name], latest: '1.0.0' })
    });

    expect(aggregated.dependencies['stale-lib@1.0.0'].maintenance?.status).toBe('stale');
    expect(aggregated.dependencies['dead-lib@1.0.0'].maintenance?.status).toBe('unmaintained');
    expect(aggregated.dependencies['fresh-lib@1.0.0'].maintenance?.status).toBe('active');
    expect(summary.unmaintainedNames).toBe(1);
  });

  it('marks archived repositories via the repo fetcher', async () => {
    const aggregated = makeAggregated({
      'archived-lib@1.0.0': makeDependency({
        name: 'archived-lib',
        direct: true,
        repository: 'git+https://github.com/owner/archived-lib.git'
      })
    });

    const summary = await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache: new MaintenanceCache(undefined),
      fetcher: async () => packument({ modified: monthsAgo(2), latest: '1.0.0' }),
      repoFetcher: async (owner, repo) => ({
        ok: true,
        status: 200,
        data: { full_name: `${owner}/${repo}`, archived: true }
      })
    });

    const dep = aggregated.dependencies['archived-lib@1.0.0'];
    expect(dep.maintenance?.status).toBe('archived');
    expect(dep.maintenance?.repoArchived).toBe(true);
    expect(summary.archivedNames).toBe(1);
  });

  it('degrades to unknown on lookup failure without touching the record surfaces', async () => {
    const aggregated = makeAggregated({ 'private-lib@1.0.0': makeDependency({ name: 'private-lib' }) });

    await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache: new MaintenanceCache(undefined),
      fetcher: async () => ({ ok: false, status: 404, error: 'HTTP 404' })
    });

    const dep = aggregated.dependencies['private-lib@1.0.0'];
    expect(dep.maintenance?.status).toBe('unknown');
    expect(dep.maintenance?.ok).toBe(false);
    expect(dep.package.deprecated).toBe(false);
    expect(dep.upgrade.blockers).toBeUndefined();
  });

  it('degrades to unknown when the time budget is exhausted', async () => {
    const aggregated = makeAggregated({ 'lib@1.0.0': makeDependency({ name: 'lib' }) });

    const summary = await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache: new MaintenanceCache(undefined),
      budgetMs: -1,
      fetcher: async () => {
        throw new Error('should not fetch');
      }
    });

    expect(aggregated.dependencies['lib@1.0.0'].maintenance?.status).toBe('unknown');
    expect(summary.attempted).toBe(0);
  });

  it('does not start archived checks after the shared deadline is spent', async () => {
    const aggregated = makeAggregated({
      'slow-lib@1.0.0': makeDependency({
        name: 'slow-lib',
        direct: true,
        repository: 'https://github.com/owner/slow-lib'
      })
    });
    let currentTime = 1_000;
    vi.spyOn(Date, 'now').mockImplementation(() => currentTime);
    let repoCalls = 0;

    await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache: new MaintenanceCache(undefined),
      budgetMs: 50,
      fetcher: async () => {
        currentTime = 1_100;
        return packument({ modified: monthsAgo(1), latest: '1.0.0' });
      },
      repoFetcher: async () => {
        repoCalls += 1;
        return { ok: true, status: 200, data: { archived: true } };
      }
    });

    expect(repoCalls).toBe(0);
    expect(aggregated.dependencies['slow-lib@1.0.0'].maintenance?.status).toBe('active');
    expect(aggregated.dependencies['slow-lib@1.0.0'].maintenance?.repoArchived).toBeUndefined();
  });

  it('backfills upgrade.latestVersion without overwriting outdated data', async () => {
    const aggregated = makeAggregated({
      'no-latest@1.0.0': makeDependency({ name: 'no-latest' }),
      'has-latest@1.0.0': makeDependency({ name: 'has-latest', latestVersion: '9.9.9' })
    });

    await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache: new MaintenanceCache(undefined),
      fetcher: async () => packument({ modified: monthsAgo(1), latest: '3.0.0' })
    });

    expect(aggregated.dependencies['no-latest@1.0.0'].upgrade.latestVersion).toBe('3.0.0');
    expect(aggregated.dependencies['has-latest@1.0.0'].upgrade.latestVersion).toBe('9.9.9');
  });

  it('serves fresh cache entries without fetching', async () => {
    const cache = new MaintenanceCache(undefined);
    cache.set('cached-lib', {
      fetchedAt: NOW.toISOString(),
      modified: monthsAgo(1),
      latestVersion: '1.2.3'
    });
    const aggregated = makeAggregated({ 'cached-lib@1.0.0': makeDependency({ name: 'cached-lib' }) });

    const summary = await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache,
      fetcher: async () => {
        throw new Error('should not fetch');
      }
    });

    const dep = aggregated.dependencies['cached-lib@1.0.0'];
    expect(dep.maintenance?.status).toBe('active');
    expect(dep.maintenance?.fromCache).toBe(true);
    expect(summary.fromCache).toBe(1);
    expect(summary.attempted).toBe(0);
  });

  it('stops archived checks after repeated failures or a 429', async () => {
    const dependencies: Record<string, DependencyRecord> = {};
    for (let i = 0; i < 8; i += 1) {
      dependencies[`lib-${i}@1.0.0`] = makeDependency({
        name: `lib-${i}`,
        direct: true,
        repository: `https://github.com/owner/lib-${i}`
      });
    }
    const aggregated = makeAggregated(dependencies);

    let repoCalls = 0;
    await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache: new MaintenanceCache(undefined),
      fetcher: async () => packument({ modified: monthsAgo(1), latest: '1.0.0' }),
      repoFetcher: async () => {
        repoCalls += 1;
        return { ok: false, status: 429, error: 'HTTP 429' };
      }
    });

    // The breaker trips on the first 429; at most one wave of concurrent
    // requests can already be in flight.
    expect(repoCalls).toBeLessThan(8);
    for (const dep of Object.values(aggregated.dependencies)) {
      expect(dep.maintenance?.repoArchived).toBeUndefined();
      expect(dep.maintenance?.status).toBe('active');
    }
  });

  it('percent-encodes every package-name segment in registry URLs', async () => {
    const requestedPaths: string[] = [];
    const server = http.createServer((req, res) => {
      requestedPaths.push(req.url || '');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ modified: monthsAgo(1), 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': {} } }));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as AddressInfo;

    try {
      const aggregated = makeAggregated({
        '@scope/pkg@1.0.0': makeDependency({ name: '@scope/pkg' })
      });
      await enrichAggregatedWithMaintenanceSignals(aggregated, {
        now: NOW,
        cache: new MaintenanceCache(undefined),
        registryUrl: `http://127.0.0.1:${port}`
      });

      expect(requestedPaths).toEqual(['/%40scope%2Fpkg']);
      expect(aggregated.dependencies['@scope/pkg@1.0.0'].maintenance?.status).toBe('active');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('caps the number of checked names, prioritizing direct dependencies', async () => {
    const aggregated = makeAggregated({
      'direct-lib@1.0.0': makeDependency({ name: 'direct-lib', direct: true }),
      'transitive-a@1.0.0': makeDependency({ name: 'transitive-a' }),
      'transitive-b@1.0.0': makeDependency({ name: 'transitive-b' })
    });

    const fetched: string[] = [];
    const summary = await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache: new MaintenanceCache(undefined),
      limit: 1,
      fetcher: async (name) => {
        fetched.push(name);
        return packument({ modified: monthsAgo(1), latest: '1.0.0' });
      }
    });

    expect(fetched).toEqual(['direct-lib']);
    expect(summary.truncatedNames).toBe(2);
    expect(aggregated.dependencies['transitive-a@1.0.0'].maintenance).toBeUndefined();
  });
});

describe('selectArchivedCheckCandidates', () => {
  it('prioritizes deprecated over direct over dormant and requires a GitHub repo', () => {
    const byName = new Map<string, DependencyRecord[]>([
      ['deprecated-lib', [makeDependency({ name: 'deprecated-lib', repository: 'https://github.com/o/deprecated-lib' })]],
      ['direct-lib', [makeDependency({ name: 'direct-lib', direct: true, repository: 'https://github.com/o/direct-lib' })]],
      ['dormant-lib', [makeDependency({ name: 'dormant-lib', repository: 'https://github.com/o/dormant-lib' })]],
      ['no-repo-lib', [makeDependency({ name: 'no-repo-lib', direct: true })]],
      ['fresh-lib', [makeDependency({ name: 'fresh-lib', repository: 'https://github.com/o/fresh-lib' })]]
    ]);
    const lookupByName = new Map([
      ['deprecated-lib', { entry: { fetchedAt: NOW.toISOString(), modified: monthsAgo(1), deprecatedVersions: { '1.0.0': 'gone' } } }],
      ['direct-lib', { entry: { fetchedAt: NOW.toISOString(), modified: monthsAgo(1) } }],
      ['dormant-lib', { entry: { fetchedAt: NOW.toISOString(), modified: monthsAgo(30) } }],
      ['no-repo-lib', { entry: { fetchedAt: NOW.toISOString(), modified: monthsAgo(1) } }],
      ['fresh-lib', { entry: { fetchedAt: NOW.toISOString(), modified: monthsAgo(1) } }]
    ]);

    const candidates = selectArchivedCheckCandidates(byName, lookupByName, NOW);
    expect(candidates.map((candidate) => candidate.name)).toEqual([
      'deprecated-lib',
      'direct-lib',
      'dormant-lib'
    ]);
  });
});

describe('registry-scoped cache keys', () => {
  it('keys cache entries by registry when a non-default registry is used', async () => {
    const cache = new MaintenanceCache(undefined);
    const aggregated = makeAggregated({ 'scoped-lib@1.0.0': makeDependency({ name: 'scoped-lib' }) });

    await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache,
      registryUrl: 'https://mirror.example.com',
      fetcher: async () => packument({ modified: monthsAgo(1), latest: '1.2.3' })
    });

    expect(cache.getFresh('https://mirror.example.com|scoped-lib', NOW)).toBeDefined();
    expect(cache.getFresh('scoped-lib', NOW)).toBeUndefined();
  });

  it('keeps bare-name cache keys for the default public registry', async () => {
    const cache = new MaintenanceCache(undefined);
    const aggregated = makeAggregated({ 'plain-lib@1.0.0': makeDependency({ name: 'plain-lib' }) });

    await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache,
      fetcher: async () => packument({ modified: monthsAgo(1), latest: '1.2.3' })
    });

    expect(cache.getFresh('plain-lib', NOW)).toBeDefined();
  });

  it('strips credentials from an explicit registryUrl before keying the cache', async () => {
    const cache = new MaintenanceCache(undefined);
    const aggregated = makeAggregated({ 'cred-lib@1.0.0': makeDependency({ name: 'cred-lib' }) });

    await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache,
      registryUrl: 'https://user:secret-token@mirror.example.com',
      fetcher: async () => packument({ modified: monthsAgo(1), latest: '1.2.3' })
    });

    expect(cache.getFresh('https://mirror.example.com|cred-lib', NOW)).toBeDefined();
    const allKeys = JSON.stringify(cache);
    expect(allKeys).not.toContain('secret-token');
  });

  it('rejects an invalid registryUrl before touching the cache or a supplied fetcher', async () => {
    const cache = new MaintenanceCache(undefined);
    // Fresh default-registry entry that must NOT satisfy the invalid-registry lookup.
    cache.set('cached-lib', {
      fetchedAt: NOW.toISOString(),
      modified: monthsAgo(1),
      latestVersion: '1.2.3'
    });
    const aggregated = makeAggregated({ 'cached-lib@1.0.0': makeDependency({ name: 'cached-lib' }) });

    const summary = await enrichAggregatedWithMaintenanceSignals(aggregated, {
      now: NOW,
      cache,
      registryUrl: 'not a valid url',
      fetcher: async () => {
        throw new Error('supplied fetcher must not be called for an invalid registry override');
      }
    });

    expect(aggregated.dependencies['cached-lib@1.0.0'].maintenance?.fromCache).not.toBe(true);
    expect(summary.fromCache).toBe(0);
    expect(summary.succeeded).toBe(0);
  });
});
