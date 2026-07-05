import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  MaintenanceCache,
  resolveMaintenanceCacheDir
} from './maintenanceCache';

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'dr-maint-cache-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

describe('resolveMaintenanceCacheDir', () => {
  it('is disabled by DEPENDENCY_RADAR_NO_CACHE=1', () => {
    expect(resolveMaintenanceCacheDir({ DEPENDENCY_RADAR_NO_CACHE: '1' })).toBeUndefined();
  });

  it('prefers DEPENDENCY_RADAR_CACHE_DIR, then XDG_CACHE_HOME', () => {
    expect(
      resolveMaintenanceCacheDir({ DEPENDENCY_RADAR_CACHE_DIR: '/custom', XDG_CACHE_HOME: '/xdg' })
    ).toBe(path.join('/custom', 'dependency-radar'));
    expect(resolveMaintenanceCacheDir({ XDG_CACHE_HOME: '/xdg' })).toBe(
      path.join('/xdg', 'dependency-radar')
    );
  });

  it('falls back to the home cache directory', () => {
    const resolved = resolveMaintenanceCacheDir({});
    expect(resolved).toContain('dependency-radar');
  });
});

describe('MaintenanceCache', () => {
  it('round-trips entries through save and load', async () => {
    const dir = await makeTempDir();
    const cache = new MaintenanceCache(dir);
    cache.set('left-pad', {
      fetchedAt: '2026-07-01T00:00:00.000Z',
      modified: '2020-01-01T00:00:00.000Z',
      latestVersion: '1.3.0'
    });
    await cache.save();

    const reloaded = new MaintenanceCache(dir);
    await reloaded.load();
    const entry = reloaded.getFresh('left-pad', new Date('2026-07-02T00:00:00.000Z'));
    expect(entry?.latestVersion).toBe('1.3.0');
  });

  it('expires entries past the TTL', async () => {
    const dir = await makeTempDir();
    const cache = new MaintenanceCache(dir);
    cache.set('old', { fetchedAt: '2026-06-01T00:00:00.000Z' });
    cache.set('fresh', { fetchedAt: '2026-06-30T00:00:00.000Z' });

    const now = new Date('2026-07-02T00:00:00.000Z');
    expect(cache.getFresh('old', now)).toBeUndefined();
    expect(cache.getFresh('fresh', now)).toBeDefined();
  });

  it('treats corrupt cache files as empty', async () => {
    const dir = await makeTempDir();
    await fs.writeFile(path.join(dir, 'registry-maintenance-v1.json'), '{corrupt');

    const cache = new MaintenanceCache(dir);
    await cache.load();
    expect(cache.getFresh('anything')).toBeUndefined();
  });

  it('discards cache files with a mismatched version', async () => {
    const dir = await makeTempDir();
    await fs.writeFile(
      path.join(dir, 'registry-maintenance-v1.json'),
      JSON.stringify({ version: 2, entries: { thing: { fetchedAt: new Date().toISOString() } } })
    );

    const cache = new MaintenanceCache(dir);
    await cache.load();
    expect(cache.getFresh('thing')).toBeUndefined();
  });

  it('is a no-op without a cache directory', async () => {
    const cache = new MaintenanceCache(undefined);
    cache.set('thing', { fetchedAt: new Date().toISOString() });
    await cache.load();
    await cache.save();
    // No throw and nothing persisted anywhere is the assertion.
    expect(cache.getFresh('thing')).toBeDefined();
  });

  it('records repo checks on existing entries', () => {
    const cache = new MaintenanceCache(undefined);
    const now = new Date('2026-07-01T00:00:00.000Z');
    cache.set('lib', { fetchedAt: now.toISOString() });
    cache.setRepoCheck('lib', true, now);
    expect(cache.getFresh('lib', now)?.repo).toEqual({
      checkedAt: now.toISOString(),
      archived: true
    });
  });
});
