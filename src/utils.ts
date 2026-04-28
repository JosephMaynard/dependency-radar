import { spawn } from 'child_process';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';

export interface CommandResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

export function runCommand(
  command: string,
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv; timeoutMs?: number; maxOutputBytes?: number } = {}
): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const validPositive = (value: unknown, fallback: number): number => {
      const parsed = typeof value === 'number' ? value : Number(value);
      return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
    };
    const timeoutMs = validPositive(options.timeoutMs ?? process.env.DEPENDENCY_RADAR_COMMAND_TIMEOUT_MS, 120_000);
    const maxOutputBytes = validPositive(options.maxOutputBytes, 50 * 1024 * 1024);
    const child = spawn(command, args, {
      cwd: options.cwd,
      shell: false,
      env: options.env ? { ...process.env, ...options.env } : process.env
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let totalBytes = 0;
    let settled = false;
    let timedOut = false;
    let outputExceeded = false;
    function terminate(): void {
      child.kill('SIGTERM');
      setTimeout(() => {
        if (!settled) child.kill('SIGKILL');
      }, 2000).unref?.();
    }

    const timer = timeoutMs > 0
      ? setTimeout(() => {
          timedOut = true;
          terminate();
        }, timeoutMs)
      : undefined;

    function collect(chunks: Buffer[], data: Buffer): void {
      const nextBytes = totalBytes + data.length;
      if (nextBytes > maxOutputBytes) {
        outputExceeded = true;
        const remaining = Math.max(0, maxOutputBytes - totalBytes);
        if (remaining > 0) chunks.push(Buffer.from(data.subarray(0, remaining)));
        totalBytes = maxOutputBytes;
        terminate();
        return;
      }
      chunks.push(Buffer.from(data));
      totalBytes = nextBytes;
    }

    child.stdout.on('data', (d) => {
      collect(stdoutChunks, Buffer.from(d));
    });
    child.stderr.on('data', (d) => {
      collect(stderrChunks, Buffer.from(d));
    });

    child.on('error', (err) => {
      if (timer) clearTimeout(timer);
      settled = true;
      reject(err);
    });
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      settled = true;
      if (timedOut) {
        reject(new Error(`${command} timed out after ${timeoutMs}ms`));
        return;
      }
      if (outputExceeded) {
        reject(new Error(`${command} output exceeded ${maxOutputBytes} bytes`));
        return;
      }
      resolve({
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        code
      });
    });
  });
}


export function getDependencyRadarVersion(): string {
  try {
    const pkgPath = path.join(__dirname, '..', 'package.json');
    const raw = fs.readFileSync(pkgPath, 'utf8');
    const pkg = JSON.parse(raw) as { version?: string };
    return pkg.version || 'unknown';
  } catch {
    return 'unknown';
  }
}

export async function ensureDir(dir: string): Promise<void> {
  await fsp.mkdir(dir, { recursive: true });
}

/**
 * Write JSON data to a file, creating parent directories as needed.
 *
 * Attempts to write a pretty-printed JSON representation of `data` to `filePath`. If pretty-printing fails due to an "Invalid string length" RangeError, falls back to a compact JSON representation.
 *
 * @param filePath - The path of the file to write
 * @param data - The value to serialize to JSON (typically JSON-serializable)
 * @throws Rethrows errors from JSON serialization (except handled "Invalid string length" for pretty-printing) and filesystem write operations
 */
export async function writeJsonFile(filePath: string, data: any): Promise<void> {
  await ensureDir(path.dirname(filePath));
  let content: string;
  try {
    content = JSON.stringify(data, null, 2);
  } catch (err) {
    // Large lockfile-derived trees can overflow string length when pretty-printing.
    if (!isInvalidStringLengthError(err)) throw err;
    content = JSON.stringify(data);
  }
  await fsp.writeFile(filePath, content, 'utf8');
}

/**
 * Determines whether a value is a RangeError whose message indicates an "Invalid string length".
 *
 * @param error - The value to inspect
 * @returns `true` if `error` is a `RangeError` with a message matching "Invalid string length" (case-insensitive), `false` otherwise.
 */
function isInvalidStringLengthError(error: unknown): boolean {
  if (!(error instanceof RangeError)) return false;
  return /Invalid string length/i.test(error.message || '');
}

/**
 * Check whether a filesystem path exists and is accessible.
 *
 * @param target - The path to check
 * @returns `true` if the path exists and is accessible, `false` otherwise
 */
export async function pathExists(target: string): Promise<boolean> {
  try {
    await fsp.access(target);
    return true;
  } catch (err) {
    return false;
  }
}

export async function removeDir(target: string): Promise<void> {
  await fsp.rm(target, { recursive: true, force: true });
}

export async function readJsonFile<T = any>(filePath: string): Promise<T> {
  const raw = await fsp.readFile(filePath, 'utf8');
  return JSON.parse(raw) as T;
}

export async function readPackageJson(projectPath: string): Promise<any> {
  const pkgPath = path.join(projectPath, 'package.json');
  const pkgRaw = await fsp.readFile(pkgPath, 'utf8');
  return JSON.parse(pkgRaw);
}

export function findBin(projectPath: string, binName: string): string {
  const ext = process.platform === 'win32' ? '.cmd' : '';
  const candidates = [
    path.join(projectPath, 'node_modules', '.bin', `${binName}${ext}`),
    path.join(process.cwd(), 'node_modules', '.bin', `${binName}${ext}`),
    path.join(__dirname, '..', 'node_modules', '.bin', `${binName}${ext}`),
    `${binName}${ext}`
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return candidates[candidates.length - 1];
}

export function licenseRiskLevel(license?: string): 'green' | 'amber' | 'red' {
  if (!license) return 'red';
  const normalized = license.toUpperCase();
  const green = ['MIT', 'BSD-2-CLAUSE', 'BSD-3-CLAUSE', 'APACHE-2.0', 'ISC'];
  const amber = ['LGPL', 'LGPL-2.1', 'LGPL-3.0', 'MPL', 'MPL-2.0'];
  if (green.includes(normalized)) return 'green';
  if (amber.includes(normalized)) return 'amber';
  return 'red';
}

export function vulnRiskLevel(counts: Record<string, number>): 'green' | 'amber' | 'red' {
  const { low = 0, moderate = 0, high = 0, critical = 0 } = counts;
  if (high > 0 || critical > 0) return 'red';
  if (low > 0 || moderate > 0) return 'amber';
  return 'green';
}

const pnpmStoreEntriesCache = new Map<string, string[]>();
const pnpmStoreIndexCache = new Map<string, Map<string, string[]>>();

function encodePnpmStoreName(pkgName: string): string {
  if (pkgName.startsWith('@')) {
    const parts = pkgName.slice(1).split('/');
    if (parts.length >= 2) {
      return `@${parts[0]}+${parts.slice(1).join('+')}`;
    }
  }
  return pkgName.replace(/\//g, '+');
}

async function getPnpmStoreEntries(pnpmDir: string): Promise<string[]> {
  if (pnpmStoreEntriesCache.has(pnpmDir)) return pnpmStoreEntriesCache.get(pnpmDir)!;
  try {
    const entries = await fsp.readdir(pnpmDir, { withFileTypes: true });
    const dirs = entries.filter((e) => e.isDirectory()).map((e) => e.name);
    pnpmStoreEntriesCache.set(pnpmDir, dirs);
    return dirs;
  } catch {
    pnpmStoreEntriesCache.set(pnpmDir, []);
    return [];
  }
}

async function getPnpmStoreIndex(pnpmDir: string): Promise<Map<string, string[]>> {
  if (pnpmStoreIndexCache.has(pnpmDir)) return pnpmStoreIndexCache.get(pnpmDir)!;
  const entries = await getPnpmStoreEntries(pnpmDir);
  const index = new Map<string, string[]>();
  for (const entry of entries) {
    const prefix = extractPnpmStoreEntryPrefix(entry);
    if (!prefix) continue;
    if (!index.has(prefix)) index.set(prefix, []);
    index.get(prefix)!.push(entry);
  }
  pnpmStoreIndexCache.set(pnpmDir, index);
  return index;
}

function extractPnpmStoreEntryPrefix(entry: string): string {
  const atIndex = entry.startsWith('@') ? entry.indexOf('@', 1) : entry.indexOf('@');
  if (atIndex <= 0) return entry.split('(')[0];
  const versionAndSuffix = entry.slice(atIndex + 1);
  const underscoreIndex = versionAndSuffix.indexOf('_');
  const parenIndex = versionAndSuffix.indexOf('(');
  let cutoff = versionAndSuffix.length;
  if (underscoreIndex >= 0) cutoff = Math.min(cutoff, underscoreIndex);
  if (parenIndex >= 0) cutoff = Math.min(cutoff, parenIndex);
  return entry.slice(0, atIndex + 1 + cutoff);
}

async function resolvePnpmPackageJsonPath(
  pkgName: string,
  version: string,
  resolvePaths: string[]
): Promise<string | undefined> {
  if (!version || version.startsWith('link:') || version.startsWith('workspace:') || version.startsWith('file:')) {
    return undefined;
  }
  const encoded = encodePnpmStoreName(pkgName);
  const prefix = `${encoded}@${version}`;
  for (const basePath of resolvePaths) {
    const pnpmDir = path.join(basePath, 'node_modules', '.pnpm');
    if (!(await pathExists(pnpmDir))) continue;
    const index = await getPnpmStoreIndex(pnpmDir);
    const matches = index.get(prefix) || [];
    for (const entry of matches) {
      const candidate = path.join(pnpmDir, entry, 'node_modules', pkgName, 'package.json');
      if (await pathExists(candidate)) return candidate;
    }
  }
  return undefined;
}

export async function resolvePackageJsonPath(
  pkgName: string,
  resolvePaths: string[],
  version?: string
): Promise<string | undefined> {
  if (version) {
    const pnpmResolved = await resolvePnpmPackageJsonPath(pkgName, version, resolvePaths);
    if (pnpmResolved) return pnpmResolved;
  }
  try {
    const direct = require.resolve(path.join(pkgName, 'package.json'), { paths: resolvePaths });
    if (direct) return direct;
  } catch {
    // fall through to entry resolution
  }

  let entryPath: string | undefined;
  try {
    entryPath = require.resolve(pkgName, { paths: resolvePaths });
  } catch {
    return undefined;
  }

  let current = path.dirname(entryPath);
  const root = path.parse(current).root;
  while (true) {
    const candidate = path.join(current, 'package.json');
    if (await pathExists(candidate)) return candidate;
    const parent = path.dirname(current);
    if (parent === current || parent === root) break;
    current = parent;
  }
  return undefined;
}

export async function readLicenseFromPackageJson(
  pkgName: string,
  resolvePaths: string[],
  version?: string
): Promise<{ license?: string; licenseFile?: string; licenseText?: string } | undefined> {
  try {
    const pkgJsonPath = await resolvePackageJsonPath(pkgName, resolvePaths, version);
    if (!pkgJsonPath) return undefined;
    return await readLicenseFromPackageDir(path.dirname(pkgJsonPath));
  } catch (err) {
    return undefined;
  }
}

export async function readLicenseFromPackageDir(
  packageDir: string
): Promise<{ license?: string; licenseFile?: string; licenseText?: string } | undefined> {
  try {
    const pkgPath = path.join(packageDir, 'package.json');
    const pkgRaw = await fsp.readFile(pkgPath, 'utf8');
    const pkg = JSON.parse(pkgRaw);
    const license = pkg.license || (Array.isArray(pkg.licenses) ? pkg.licenses.map((l: any) => (typeof l === 'string' ? l : l?.type)).filter(Boolean).join(' OR ') : undefined);
    const licenseFile = await findLicenseFile(packageDir);
    if (!license && !licenseFile) return undefined;
    let licenseText: string | undefined;
    if (licenseFile) {
      try {
        licenseText = await fsp.readFile(licenseFile, 'utf8');
      } catch {
        licenseText = undefined;
      }
    }
    return { license, licenseFile, licenseText };
  } catch {
    return undefined;
  }
}

async function findLicenseFile(dir: string): Promise<string | undefined> {
  try {
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    const fileNames = entries.filter((e) => e.isFile()).map((e) => e.name);
    const patterns = [/^licen[cs]e(\.|$)/, /^copying(\.|$)/, /^notice(\.|$)/];
    const match = fileNames.find((name) => {
      const lower = name.toLowerCase();
      return patterns.some((pattern) => pattern.test(lower));
    });
    return match ? path.join(dir, match) : undefined;
  } catch {
    return undefined;
  }
}

export async function findLockDir(startPath: string, lockFiles: string[]): Promise<string | undefined> {
  let current = startPath;
  while (true) {
    for (const file of lockFiles) {
      if (await pathExists(path.join(current, file))) {
        return current;
      }
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return undefined;
}

export function parseJsonOutput(raw: string): any | undefined {
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const parsed: any[] = [];
    for (const line of lines) {
      try {
        parsed.push(JSON.parse(line));
      } catch {
        // ignore non-JSON lines
      }
    }
    return parsed.length > 0 ? parsed : undefined;
  }
}
