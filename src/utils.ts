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
  options: { cwd?: string } = {}
): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      shell: false
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];

    child.stdout.on('data', (d) => stdoutChunks.push(Buffer.from(d)));
    child.stderr.on('data', (d) => stderrChunks.push(Buffer.from(d)));

    child.on('error', (err) => reject(err));
    child.on('close', (code) => {
      resolve({
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        code
      });
    });
  });
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

export async function writeJsonFile(filePath: string, data: any): Promise<void> {
  await ensureDir(path.dirname(filePath));
  const content = JSON.stringify(data, null, 2);
  await fsp.writeFile(filePath, content, 'utf8');
}

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

export function maintenanceRisk(lastPublished?: string): 'green' | 'amber' | 'red' | 'unknown' {
  if (!lastPublished) return 'unknown';
  const last = new Date(lastPublished).getTime();
  if (Number.isNaN(last)) return 'unknown';
  const now = Date.now();
  const months = (now - last) / (1000 * 60 * 60 * 24 * 30);
  if (months <= 12) return 'green';
  if (months <= 36) return 'amber';
  return 'red';
}

export async function readLicenseFromPackageJson(
  pkgName: string,
  projectPath: string
): Promise<{ license?: string; licenseFile?: string } | undefined> {
  try {
    const pkgJsonPath = require.resolve(path.join(pkgName, 'package.json'), { paths: [projectPath] });
    const pkgRaw = await fsp.readFile(pkgJsonPath, 'utf8');
    const pkg = JSON.parse(pkgRaw);
    const license = pkg.license || (Array.isArray(pkg.licenses) ? pkg.licenses.map((l: any) => (typeof l === 'string' ? l : l?.type)).filter(Boolean).join(' OR ') : undefined);
    const licenseFile = await findLicenseFile(path.dirname(pkgJsonPath));
    if (!license && !licenseFile) return undefined;
    return { license, licenseFile };
  } catch (err) {
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
