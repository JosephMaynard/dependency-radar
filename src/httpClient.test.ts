import http from 'http';
import { AddressInfo } from 'net';
import { afterEach, describe, expect, it } from 'vitest';
import { httpGetJson, mapWithConcurrency } from './httpClient';

const servers: http.Server[] = [];

async function startServer(handler: http.RequestListener): Promise<string> {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return `http://127.0.0.1:${port}`;
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) => new Promise<void>((resolve) => server.close(() => resolve()))
    )
  );
});

describe('httpGetJson', () => {
  it('returns parsed JSON for a 2xx response and sends headers', async () => {
    let receivedAccept: string | undefined;
    const base = await startServer((req, res) => {
      receivedAccept = req.headers.accept;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ hello: 'world' }));
    });

    const result = await httpGetJson(`${base}/thing`, {
      headers: { Accept: 'application/vnd.npm.install-v1+json' }
    });
    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.data).toEqual({ hello: 'world' });
    expect(receivedAccept).toBe('application/vnd.npm.install-v1+json');
  });

  it('reports non-2xx statuses without throwing', async () => {
    const base = await startServer((_req, res) => {
      res.writeHead(404);
      res.end('nope');
    });

    const result = await httpGetJson(base);
    expect(result.ok).toBe(false);
    expect(result.status).toBe(404);
  });

  it('reports malformed JSON', async () => {
    const base = await startServer((_req, res) => {
      res.writeHead(200);
      res.end('{not json');
    });

    const result = await httpGetJson(base);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid JSON response');
  });

  it('times out slow responses', async () => {
    const base = await startServer(() => {
      // Never respond.
    });

    const result = await httpGetJson(base, { timeoutMs: 100 });
    expect(result.ok).toBe(false);
    expect(result.error).toContain('timed out');
  });

  it('aborts responses over the size cap', async () => {
    const base = await startServer((_req, res) => {
      res.writeHead(200);
      res.end(JSON.stringify({ payload: 'x'.repeat(64 * 1024) }));
    });

    const result = await httpGetJson(base, { maxBytes: 1024 });
    expect(result.ok).toBe(false);
    expect(result.error).toContain('exceeded');
  });

  it('follows redirects up to the cap', async () => {
    const visited: string[] = [];
    const base = await startServer((req, res) => {
      visited.push(req.url || '');
      if (req.url === '/start') {
        res.writeHead(302, { Location: '/end' });
        res.end();
        return;
      }
      res.writeHead(200);
      res.end(JSON.stringify({ arrived: true }));
    });

    const result = await httpGetJson(`${base}/start`);
    expect(result.ok).toBe(true);
    expect(result.data).toEqual({ arrived: true });
    expect(visited).toEqual(['/start', '/end']);
  });

  it('fails on redirect loops', async () => {
    const base = await startServer((_req, res) => {
      res.writeHead(302, { Location: '/loop' });
      res.end();
    });

    const result = await httpGetJson(`${base}/loop`, { maxRedirects: 2 });
    expect(result.ok).toBe(false);
    expect(result.error).toBe('too many redirects');
  });

  it('rejects unsupported protocols and invalid URLs without throwing', async () => {
    expect((await httpGetJson('ftp://example.test')).ok).toBe(false);
    expect((await httpGetJson('not a url')).ok).toBe(false);
  });
});

describe('mapWithConcurrency', () => {
  it('preserves order and respects the concurrency limit', async () => {
    let active = 0;
    let peak = 0;
    const items = [1, 2, 3, 4, 5, 6];

    const results = await mapWithConcurrency(items, 2, Infinity, async (item) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 10));
      active -= 1;
      return item * 10;
    });

    expect(results).toEqual([10, 20, 30, 40, 50, 60]);
    expect(peak).toBeLessThanOrEqual(2);
  });

  it('skips items past the deadline via the placeholder factory', async () => {
    const results = await mapWithConcurrency(
      ['a', 'b'],
      2,
      Date.now() - 1,
      async (item) => item.toUpperCase(),
      (item) => `skipped:${item}`
    );

    expect(results).toEqual(['skipped:a', 'skipped:b']);
  });

  it('captures mapper throws as placeholder results', async () => {
    const results = await mapWithConcurrency(
      [1, 2],
      2,
      Infinity,
      async (item) => {
        if (item === 1) throw new Error('boom');
        return item;
      },
      () => -1
    );

    expect(results).toEqual([-1, 2]);
  });
});
