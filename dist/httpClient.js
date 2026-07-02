"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.httpGetJson = httpGetJson;
exports.mapWithConcurrency = mapWithConcurrency;
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const url_1 = require("url");
const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_REDIRECTS = 3;
const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
/**
 * Fetch a URL and parse the response body as JSON.
 *
 * Designed for best-effort enrichment lookups: this function never throws.
 * Any transport, timeout, size, status, or parse problem is reported through
 * the returned result object instead.
 *
 * Node 14-safe by construction: no global fetch, no AbortController-based
 * request cancellation. Timeouts destroy the request directly and responses
 * are size-capped by counting bytes as they arrive. No Accept-Encoding header
 * is sent, so responses arrive identity-encoded and need no decompression.
 *
 * @param url - Absolute http(s) URL to fetch.
 * @param options - Headers, timeout, size cap, redirect cap, and keep-alive agent.
 * @returns A result object; `ok` is true only for a 2xx response with valid JSON.
 */
function httpGetJson(url, options = {}) {
    var _a, _b, _c;
    const timeoutMs = (_a = options.timeoutMs) !== null && _a !== void 0 ? _a : DEFAULT_TIMEOUT_MS;
    const maxBytes = (_b = options.maxBytes) !== null && _b !== void 0 ? _b : DEFAULT_MAX_BYTES;
    const maxRedirects = (_c = options.maxRedirects) !== null && _c !== void 0 ? _c : DEFAULT_MAX_REDIRECTS;
    const requestOnce = (target, redirectsLeft) => new Promise((resolve) => {
        let parsed;
        try {
            parsed = new url_1.URL(target);
        }
        catch {
            resolve({ ok: false, error: `invalid URL: ${target}` });
            return;
        }
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
            resolve({ ok: false, error: `unsupported protocol: ${parsed.protocol}` });
            return;
        }
        const transport = parsed.protocol === 'https:' ? https_1.default : http_1.default;
        let settled = false;
        const settle = (result) => {
            if (settled)
                return;
            settled = true;
            resolve(result);
        };
        const req = transport.get(parsed, {
            headers: options.headers,
            agent: options.agent
        }, (res) => {
            var _a;
            const status = (_a = res.statusCode) !== null && _a !== void 0 ? _a : 0;
            if (REDIRECT_STATUS_CODES.has(status) && res.headers.location) {
                res.resume();
                if (redirectsLeft <= 0) {
                    settle({ ok: false, status, error: 'too many redirects' });
                    return;
                }
                let nextUrl;
                try {
                    nextUrl = new url_1.URL(res.headers.location, parsed).toString();
                }
                catch {
                    settle({ ok: false, status, error: `invalid redirect location: ${res.headers.location}` });
                    return;
                }
                requestOnce(nextUrl, redirectsLeft - 1).then(settle);
                return;
            }
            let received = 0;
            const chunks = [];
            res.on('data', (chunk) => {
                received += chunk.length;
                if (received > maxBytes) {
                    res.destroy();
                    settle({ ok: false, status, error: `response exceeded ${maxBytes} bytes` });
                    return;
                }
                chunks.push(chunk);
            });
            res.on('error', (err) => {
                settle({ ok: false, status, error: err instanceof Error ? err.message : String(err) });
            });
            res.on('end', () => {
                if (settled)
                    return;
                if (status < 200 || status >= 300) {
                    settle({ ok: false, status, error: `HTTP ${status}` });
                    return;
                }
                try {
                    const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
                    settle({ ok: true, status, data });
                }
                catch {
                    settle({ ok: false, status, error: 'invalid JSON response' });
                }
            });
        });
        const timer = setTimeout(() => {
            req.destroy(new Error(`request timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        // Do not keep the process alive just for the timeout timer.
        if (typeof timer.unref === 'function')
            timer.unref();
        req.on('error', (err) => {
            clearTimeout(timer);
            settle({ ok: false, error: err instanceof Error ? err.message : String(err) });
        });
        req.on('close', () => {
            clearTimeout(timer);
        });
    });
    return requestOnce(url, maxRedirects);
}
/**
 * Run an async mapper over items with bounded concurrency and a hard deadline.
 *
 * Unlike batch-based slicing, this is a true worker pool: each worker pulls
 * the next item as soon as it finishes, keeping connections saturated. The
 * deadline is checked before each dispatch; items past the deadline resolve
 * through `onDeadline` (or `undefined` when not provided) without running.
 *
 * @param items - Items to process in order.
 * @param limit - Maximum number of mappers running at once (minimum 1).
 * @param deadline - Epoch milliseconds after which remaining items are skipped; pass Infinity for no deadline.
 * @param fn - Async mapper receiving the item and its index.
 * @param onDeadline - Optional factory for the placeholder result of skipped items.
 * @returns Results in input order; skipped items hold the `onDeadline` value.
 */
async function mapWithConcurrency(items, limit, deadline, fn, onDeadline) {
    const results = new Array(items.length);
    let nextIndex = 0;
    const worker = async () => {
        while (true) {
            const index = nextIndex;
            if (index >= items.length)
                return;
            nextIndex += 1;
            const item = items[index];
            if (Date.now() > deadline) {
                results[index] = onDeadline ? onDeadline(item, index) : undefined;
                continue;
            }
            try {
                results[index] = await fn(item, index);
            }
            catch {
                // Mappers are expected to capture their own failures; a throw here
                // must not take down the pool or the scan.
                results[index] = onDeadline ? onDeadline(item, index) : undefined;
            }
        }
    };
    const workerCount = Math.max(1, Math.min(limit, items.length));
    const workers = [];
    for (let i = 0; i < workerCount; i += 1) {
        workers.push(worker());
    }
    await Promise.all(workers);
    return results;
}
