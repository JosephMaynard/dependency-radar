import fs from 'fs/promises';
import path from 'path';
import type { SupplyChainSignal, ToolResult } from '../types';
import { pathExists, runCommand, writeJsonFile } from '../utils';

const DEFAULT_REGISTRY_HOSTS = new Set(['registry.npmjs.org']);

type LockfileSignalOptions = {
  persistToDisk?: boolean;
  auditSignatures?: boolean;
  offline?: boolean;
  expectedRegistryHosts?: string[];
};

function stripJsonComments(raw: string): string {
  let out = '';
  let quote: string | undefined;
  let escaped = false;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    const next = raw[i + 1];
    if (quote) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; out += ch; continue; }
    if (ch === '/' && next === '/') {
      while (i < raw.length && raw[i] !== '\n') i += 1;
      out += '\n';
      continue;
    }
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < raw.length && !(raw[i] === '*' && raw[i + 1] === '/')) i += 1;
      i += 1;
      continue;
    }
    out += ch;
  }
  return out.replace(/,\s*([}\]])/g, '$1');
}

type NpmLockEntry = {
  version?: string;
  resolved?: string;
  integrity?: string;
};

type NpmLockObject = {
  packages?: Record<string, NpmLockEntry>;
  dependencies?: Record<string, NpmLockEntry>;
};

function normalizeExpectedHosts(hosts?: string[]): Set<string> {
  const normalized = new Set(DEFAULT_REGISTRY_HOSTS);
  for (const host of hosts || []) {
    const trimmed = host.trim().toLowerCase();
    if (trimmed) normalized.add(trimmed);
  }
  return normalized;
}

function addSignal(
  signals: SupplyChainSignal[],
  seen: Set<string>,
  signal: SupplyChainSignal
): void {
  const key = `${signal.type}|${signal.packageName || ''}|${signal.packageVersion || ''}|${signal.source}|${signal.detail}`;
  if (seen.has(key)) return;
  seen.add(key);
  signals.push(signal);
}

function packageFromKey(key: string): { name?: string; version?: string } {
  const cleaned = key.replace(/^\/?/, '');
  const afterLastNodeModules = cleaned.split('/node_modules/').pop()?.replace(/^node_modules\//, '') || cleaned;
  const parts = afterLastNodeModules.split('/').filter(Boolean);
  if (parts[0]?.startsWith('@') && parts[1]) {
    return { name: `${parts[0]}/${parts[1]}` };
  }
  return { name: parts[0] || undefined };
}

function packageNameFromSelector(selector: string): string | undefined {
  const first = selector.split(',')[0]?.trim();
  if (!first) return undefined;
  const normalized = first.replace(/^["']|["']$/g, '');
  if (normalized.startsWith('@')) {
    const parts = normalized.split('@');
    const scopedName = parts.length >= 3 ? `@${parts[1]}` : normalized;
    return scopedName || undefined;
  }
  const atIndex = normalized.indexOf('@');
  return atIndex > 0 ? normalized.slice(0, atIndex) : normalized;
}

function inspectResolvedUrl(
  signals: SupplyChainSignal[],
  seen: Set<string>,
  sourceFile: string,
  packageName: string | undefined,
  packageVersion: string | undefined,
  value: string,
  expectedHosts: Set<string>
): void {
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
  if (!/^https?:\/\//i.test(value)) return;
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
  } catch {
    // Ignore malformed URL strings.
  }
}

function inspectNpmLockObject(
  obj: NpmLockObject,
  sourceFile: string,
  expectedHosts: Set<string>
): SupplyChainSignal[] {
  const signals: SupplyChainSignal[] = [];
  const seen = new Set<string>();
  const packages = obj?.packages && typeof obj.packages === 'object'
    ? obj.packages
    : undefined;
  if (packages) {
    for (const [key, entry] of Object.entries<any>(packages)) {
      if (!entry || typeof entry !== 'object' || key === '') continue;
      const pkg = packageFromKey(key);
      const resolved = typeof entry.resolved === 'string' ? entry.resolved : '';
      if (resolved) inspectResolvedUrl(signals, seen, sourceFile, pkg.name, entry.version || pkg.version, resolved, expectedHosts);
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
  const dependencies = obj?.dependencies && typeof obj.dependencies === 'object' ? obj.dependencies : {};
  for (const [name, entry] of Object.entries<any>(dependencies)) {
    if (!entry || typeof entry !== 'object') continue;
    const resolved = typeof entry.resolved === 'string' ? entry.resolved : '';
    if (resolved) inspectResolvedUrl(signals, seen, sourceFile, name, entry.version, resolved, expectedHosts);
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

function inspectTextLock(
  raw: string,
  sourceFile: string,
  expectedHosts: Set<string>
): SupplyChainSignal[] {
  const signals: SupplyChainSignal[] = [];
  const seen = new Set<string>();
  let currentName: string | undefined;
  let currentVersion: string | undefined;
  let currentHasIntegrity = false;
  let currentResolved = '';

  const flush = (): void => {
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
    if (!line || line.startsWith('#')) continue;
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
    if (versionMatch) currentVersion = versionMatch[1];
    const resolvedMatch = line.match(/^(resolved|resolution)\s+["']?([^"']+)["']?/);
    if (resolvedMatch) {
      currentResolved = resolvedMatch[2];
      inspectResolvedUrl(signals, seen, sourceFile, currentName, currentVersion, currentResolved, expectedHosts);
    }
    if (/^integrity\s+/.test(line) || /checksum:\s+/.test(line)) {
      currentHasIntegrity = true;
    }
    const specMatch = line.match(/(?:^|["'\s])((?:git\+|git:\/\/|github:|file:|link:|portal:|https?:\/\/)[^"'\s]+)/);
    if (specMatch) inspectResolvedUrl(signals, seen, sourceFile, currentName, currentVersion, specMatch[1], expectedHosts);
  }
  flush();
  return signals;
}

async function collectLockfileSignals(
  projectPath: string,
  expectedHosts: Set<string>
): Promise<SupplyChainSignal[]> {
  const signals: SupplyChainSignal[] = [];
  const candidates = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock'];
  for (const fileName of candidates) {
    const filePath = path.join(projectPath, fileName);
    if (!(await pathExists(filePath))) continue;
    const raw = await fs.readFile(filePath, 'utf8');
    if (fileName === 'package-lock.json' || fileName === 'npm-shrinkwrap.json') {
      try {
        signals.push(...inspectNpmLockObject(JSON.parse(raw), fileName, expectedHosts));
      } catch {
        signals.push(...inspectTextLock(raw, fileName, expectedHosts));
      }
    } else if (fileName === 'bun.lock' && raw.trim().startsWith('{')) {
      try {
        signals.push(...inspectNpmLockObject(JSON.parse(stripJsonComments(raw)), fileName, expectedHosts));
      } catch {
        signals.push(...inspectTextLock(raw, fileName, expectedHosts));
      }
    } else {
      signals.push(...inspectTextLock(raw, fileName, expectedHosts));
    }
  }
  return signals;
}

type SignatureAuditResult = {
  attempted: boolean;
  ok: boolean;
  status?: 'verified' | 'failed' | 'skipped';
  output?: string;
  error?: string;
};

async function runNpmAuditSignatures(projectPath: string): Promise<SignatureAuditResult> {
  try {
    const result = await runCommand('npm', ['audit', 'signatures'], { cwd: projectPath });
    const output = `${result.stdout || ''}${result.stderr ? `\n${result.stderr}` : ''}`.trim();
    return {
      attempted: true,
      ok: result.code === 0,
      status: result.code === 0 ? 'verified' : 'failed',
      ...(output ? { output } : {}),
      ...(result.code === 0 ? {} : { error: `npm audit signatures exited with code ${result.code}` })
    };
  } catch (err: any) {
    return {
      attempted: true,
      ok: false,
      status: 'failed',
      error: err instanceof Error ? err.message : String(err)
    };
  }
}

export async function runLockfileSupplyChainSignals(
  projectPath: string,
  tempDir: string,
  options: LockfileSignalOptions = {}
): Promise<ToolResult<{
  signals: SupplyChainSignal[];
  signatureAudit?: SignatureAuditResult;
}>> {
  const persistToDisk = options.persistToDisk !== false;
  const targetFile = path.join(tempDir, 'supply-chain-signals.json');
  try {
    const signals = await collectLockfileSignals(
      projectPath,
      normalizeExpectedHosts(options.expectedRegistryHosts)
    );
    const signatureAudit = options.auditSignatures && !options.offline
      ? await runNpmAuditSignatures(projectPath)
      : options.auditSignatures && options.offline
        ? { attempted: false, ok: false, status: 'skipped' as const, error: 'skipped (--offline)' }
        : undefined;
    const data = {
      signals,
      ...(signatureAudit ? { signatureAudit } : {})
    };
    if (persistToDisk) await writeJsonFile(targetFile, data);
    return { ok: true, data, ...(persistToDisk ? { file: targetFile } : {}) };
  } catch (err: any) {
    if (persistToDisk) await writeJsonFile(targetFile, { error: String(err) });
    return {
      ok: false,
      error: `lockfile supply-chain signal collection failed: ${String(err)}`,
      ...(persistToDisk ? { file: targetFile } : {})
    };
  }
}
