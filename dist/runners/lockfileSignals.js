"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runLockfileSupplyChainSignals = runLockfileSupplyChainSignals;
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const utils_1 = require("../utils");
// registry.yarnpkg.com is Yarn Classic's default alias for the npm registry;
// treating it as unexpected flags every ordinary Yarn lockfile.
const DEFAULT_REGISTRY_HOSTS = new Set(['registry.npmjs.org', 'registry.yarnpkg.com']);
function stripJsonComments(raw) {
    let out = '';
    let quote;
    let escaped = false;
    for (let i = 0; i < raw.length; i += 1) {
        const ch = raw[i];
        const next = raw[i + 1];
        if (quote) {
            out += ch;
            if (escaped)
                escaped = false;
            else if (ch === '\\')
                escaped = true;
            else if (ch === quote)
                quote = undefined;
            continue;
        }
        if (ch === '"' || ch === "'") {
            quote = ch;
            out += ch;
            continue;
        }
        if (ch === '/' && next === '/') {
            while (i < raw.length && raw[i] !== '\n')
                i += 1;
            out += '\n';
            continue;
        }
        if (ch === '/' && next === '*') {
            i += 2;
            while (i < raw.length && !(raw[i] === '*' && raw[i + 1] === '/'))
                i += 1;
            i += 1;
            continue;
        }
        out += ch;
    }
    return out.replace(/,\s*([}\]])/g, '$1');
}
function normalizeExpectedHosts(hosts) {
    const normalized = new Set(DEFAULT_REGISTRY_HOSTS);
    for (const host of hosts || []) {
        const trimmed = host.trim().toLowerCase();
        if (trimmed)
            normalized.add(trimmed);
    }
    return normalized;
}
function addSignal(signals, seen, signal) {
    const key = `${signal.type}|${signal.packageName || ''}|${signal.packageVersion || ''}|${signal.source}|${signal.detail}`;
    if (seen.has(key))
        return;
    seen.add(key);
    signals.push(signal);
}
function packageFromKey(key) {
    var _a, _b;
    const cleaned = key.replace(/^\/?/, '');
    const afterLastNodeModules = ((_a = cleaned.split('/node_modules/').pop()) === null || _a === void 0 ? void 0 : _a.replace(/^node_modules\//, '')) || cleaned;
    const parts = afterLastNodeModules.split('/').filter(Boolean);
    if (((_b = parts[0]) === null || _b === void 0 ? void 0 : _b.startsWith('@')) && parts[1]) {
        return { name: `${parts[0]}/${parts[1]}` };
    }
    return { name: parts[0] || undefined };
}
function packageNameFromSelector(selector) {
    var _a;
    const first = (_a = selector.split(',')[0]) === null || _a === void 0 ? void 0 : _a.trim();
    if (!first)
        return undefined;
    const normalized = first.replace(/^["']|["']$/g, '');
    if (normalized.startsWith('@')) {
        const parts = normalized.split('@');
        const scopedName = parts.length >= 3 ? `@${parts[1]}` : normalized;
        return scopedName || undefined;
    }
    const atIndex = normalized.indexOf('@');
    return atIndex > 0 ? normalized.slice(0, atIndex) : normalized;
}
function inspectResolvedUrl(signals, seen, sourceFile, packageName, packageVersion, value, expectedHosts) {
    const lower = value.toLowerCase();
    if (lower.startsWith('git+') || lower.startsWith('git://') || lower.startsWith('github:') || lower.includes('github.com:')) {
        addSignal(signals, seen, {
            type: 'git-dependency',
            packageName,
            packageVersion,
            source: sourceFile,
            detail: `${packageName || 'dependency'} resolves from git source ${value}`
        });
        return;
    }
    if (lower.startsWith('file:') || lower.startsWith('link:') || lower.startsWith('portal:')) {
        addSignal(signals, seen, {
            type: 'file-dependency',
            packageName,
            packageVersion,
            source: sourceFile,
            detail: `${packageName || 'dependency'} resolves from local source ${value}`
        });
        return;
    }
    if (!/^https?:\/\//i.test(value))
        return;
    try {
        const url = new URL(value);
        const host = url.host.toLowerCase();
        if (!expectedHosts.has(host)) {
            addSignal(signals, seen, {
                type: value.endsWith('.tgz') ? 'non-registry-tarball' : 'unexpected-registry-host',
                packageName,
                packageVersion,
                source: sourceFile,
                detail: `${packageName || 'dependency'} resolves from ${host}`
            });
        }
    }
    catch {
        // Ignore malformed URL strings.
    }
}
function inspectNpmLockObject(obj, sourceFile, expectedHosts) {
    const signals = [];
    const seen = new Set();
    const packages = (obj === null || obj === void 0 ? void 0 : obj.packages) && typeof obj.packages === 'object'
        ? obj.packages
        : undefined;
    if (packages) {
        for (const [key, entry] of Object.entries(packages)) {
            if (!entry || typeof entry !== 'object' || key === '')
                continue;
            const pkg = packageFromKey(key);
            const resolved = typeof entry.resolved === 'string' ? entry.resolved : '';
            if (resolved)
                inspectResolvedUrl(signals, seen, sourceFile, pkg.name, entry.version || pkg.version, resolved, expectedHosts);
            if (resolved && !entry.integrity && !resolved.startsWith('file:') && !resolved.startsWith('link:')) {
                addSignal(signals, seen, {
                    type: 'missing-integrity',
                    packageName: pkg.name,
                    packageVersion: entry.version || pkg.version,
                    source: sourceFile,
                    detail: `${pkg.name || key} has a resolved source but no integrity field`
                });
            }
        }
        return signals;
    }
    const dependencies = (obj === null || obj === void 0 ? void 0 : obj.dependencies) && typeof obj.dependencies === 'object' ? obj.dependencies : {};
    for (const [name, entry] of Object.entries(dependencies)) {
        if (!entry || typeof entry !== 'object')
            continue;
        const resolved = typeof entry.resolved === 'string' ? entry.resolved : '';
        if (resolved)
            inspectResolvedUrl(signals, seen, sourceFile, name, entry.version, resolved, expectedHosts);
        if (resolved && !entry.integrity && !resolved.startsWith('file:') && !resolved.startsWith('link:')) {
            addSignal(signals, seen, {
                type: 'missing-integrity',
                packageName: name,
                packageVersion: entry.version,
                source: sourceFile,
                detail: `${name} has a resolved source but no integrity field`
            });
        }
    }
    return signals;
}
function inspectTextLock(raw, sourceFile, expectedHosts) {
    const signals = [];
    const seen = new Set();
    let currentName;
    let currentVersion;
    let currentHasIntegrity = false;
    let currentResolved = '';
    const flush = () => {
        if (currentResolved && !currentHasIntegrity && !currentResolved.startsWith('file:') && !currentResolved.startsWith('link:')) {
            addSignal(signals, seen, {
                type: 'missing-integrity',
                packageName: currentName,
                packageVersion: currentVersion,
                source: sourceFile,
                detail: `${currentName || 'dependency'} has a resolved source but no integrity field`
            });
        }
    };
    for (const rawLine of raw.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#'))
            continue;
        if (!rawLine.startsWith(' ') && line.endsWith(':')) {
            flush();
            currentHasIntegrity = false;
            currentResolved = '';
            const selector = line.slice(0, -1).replace(/^["']|["']$/g, '');
            currentName = packageNameFromSelector(selector);
            currentVersion = undefined;
            continue;
        }
        const versionMatch = line.match(/^version\s+["']?([^"'\s]+)["']?/);
        if (versionMatch)
            currentVersion = versionMatch[1];
        const resolvedMatch = line.match(/^(resolved|resolution)\s+["']?([^"']+)["']?/);
        if (resolvedMatch) {
            currentResolved = resolvedMatch[2];
            inspectResolvedUrl(signals, seen, sourceFile, currentName, currentVersion, currentResolved, expectedHosts);
        }
        if (/^integrity\s+/.test(line) || /checksum:\s+/.test(line)) {
            currentHasIntegrity = true;
        }
        const specMatch = line.match(/(?:^|["'\s])((?:git\+|git:\/\/|github:|file:|link:|portal:|https?:\/\/)[^"'\s]+)/);
        if (specMatch)
            inspectResolvedUrl(signals, seen, sourceFile, currentName, currentVersion, specMatch[1], expectedHosts);
    }
    flush();
    return signals;
}
async function collectLockfileSignals(projectPath, expectedHosts) {
    var _a;
    const signals = [];
    let lockfilesFound = 0;
    const candidates = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock'];
    // Read the same lockfile the audit/outdated collectors use: the project's
    // own, or a workspace root's (findLockDir bounds the walk so an unrelated
    // ancestor project is never borrowed).
    const lockDir = (_a = (await (0, utils_1.findLockDir)(projectPath, candidates))) !== null && _a !== void 0 ? _a : projectPath;
    for (const fileName of candidates) {
        const filePath = path_1.default.join(lockDir, fileName);
        if (!(await (0, utils_1.pathExists)(filePath)))
            continue;
        lockfilesFound += 1;
        const raw = await promises_1.default.readFile(filePath, 'utf8');
        if (fileName === 'package-lock.json' || fileName === 'npm-shrinkwrap.json') {
            try {
                signals.push(...inspectNpmLockObject(JSON.parse(raw), fileName, expectedHosts));
            }
            catch {
                signals.push(...inspectTextLock(raw, fileName, expectedHosts));
            }
        }
        else if (fileName === 'bun.lock' && raw.trim().startsWith('{')) {
            try {
                signals.push(...inspectNpmLockObject(JSON.parse(stripJsonComments(raw)), fileName, expectedHosts));
            }
            catch {
                signals.push(...inspectTextLock(raw, fileName, expectedHosts));
            }
        }
        else {
            signals.push(...inspectTextLock(raw, fileName, expectedHosts));
        }
    }
    return { signals, lockfilesFound };
}
async function runNpmAuditSignatures(projectPath) {
    try {
        const result = await (0, utils_1.runCommand)('npm', ['audit', 'signatures'], { cwd: projectPath });
        const output = `${result.stdout || ''}${result.stderr ? `\n${result.stderr}` : ''}`.trim();
        return {
            attempted: true,
            ok: result.code === 0,
            status: result.code === 0 ? 'verified' : 'failed',
            ...(output ? { output } : {}),
            ...(result.code === 0 ? {} : { error: `npm audit signatures exited with code ${result.code}` })
        };
    }
    catch (err) {
        return {
            attempted: true,
            ok: false,
            status: 'failed',
            error: err instanceof Error ? err.message : String(err)
        };
    }
}
async function runLockfileSupplyChainSignals(projectPath, tempDir, options = {}) {
    const persistToDisk = options.persistToDisk !== false;
    const targetFile = path_1.default.join(tempDir, 'supply-chain-signals.json');
    try {
        const { signals, lockfilesFound } = await collectLockfileSignals(projectPath, normalizeExpectedHosts(options.expectedRegistryHosts));
        const signatureAudit = options.auditSignatures && !options.offline
            ? await runNpmAuditSignatures(projectPath)
            : options.auditSignatures && options.offline
                ? { attempted: false, ok: false, status: 'skipped', error: 'skipped (--offline)' }
                : undefined;
        const data = {
            signals,
            lockfilesFound,
            ...(signatureAudit ? { signatureAudit } : {})
        };
        if (persistToDisk)
            await (0, utils_1.writeJsonFile)(targetFile, data);
        return { ok: true, data, ...(persistToDisk ? { file: targetFile } : {}) };
    }
    catch (err) {
        if (persistToDisk)
            await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        return {
            ok: false,
            error: `lockfile supply-chain signal collection failed: ${String(err)}`,
            ...(persistToDisk ? { file: targetFile } : {})
        };
    }
}
