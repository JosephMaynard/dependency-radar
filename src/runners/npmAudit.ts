import path from 'path';
import fs from 'fs/promises';
import { ToolResult } from '../types';
import { runCommand, writeJsonFile } from '../utils';

async function pathExists(target: string): Promise<boolean> {
  try {
    await fs.stat(target);
    return true;
  } catch {
    return false;
  }
}

async function findLockDir(startPath: string, lockFiles: string[]): Promise<string | undefined> {
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

function parseJsonOutput(raw: string): any | undefined {
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

function normalizeAuditOutput(tool: 'npm' | 'pnpm' | 'yarn', data: any): any | undefined {
  if (!data) return undefined;
  if (data.vulnerabilities || data.advisories) return data;

  // Yarn (classic/berry) often emits JSONL with auditAdvisory entries.
  const entries = Array.isArray(data) ? data : [data];
  const advisories: Record<string, any> = {};
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue;
    if (entry.type === 'auditAdvisory' && entry.data?.advisory) {
      const adv = entry.data.advisory;
      const key = String(adv.id || adv.github_advisory_id || `${adv.module_name || adv.module}:${adv.title || 'advisory'}`);
      advisories[key] = adv;
    }
  }
  if (Object.keys(advisories).length > 0) {
    return { advisories };
  }

  if (tool === 'pnpm' && data.result && data.advisories) {
    return data;
  }

  return undefined;
}

function buildAuditCommand(tool: 'npm' | 'pnpm' | 'yarn', yarnVersion?: string): { cmd: string; args: string[]; lockFiles: string[] } {
  if (tool === 'pnpm') {
    return { cmd: 'pnpm', args: ['audit', '--json'], lockFiles: ['pnpm-lock.yaml'] };
  }
  if (tool === 'yarn') {
    const major = yarnVersion ? Number.parseInt(yarnVersion.split('.')[0], 10) : NaN;
    if (!Number.isNaN(major) && major >= 2) {
      return { cmd: 'yarn', args: ['npm', 'audit', '--all', '--json'], lockFiles: ['yarn.lock'] };
    }
    return { cmd: 'yarn', args: ['audit', '--json'], lockFiles: ['yarn.lock'] };
  }
  return { cmd: 'npm', args: ['audit', '--json'], lockFiles: ['package-lock.json', 'npm-shrinkwrap.json'] };
}

export async function runPackageAudit(
  projectPath: string,
  tempDir: string,
  tool: 'npm' | 'pnpm' | 'yarn',
  yarnVersion?: string
): Promise<ToolResult<any>> {
  const targetFile = path.join(tempDir, `${tool}-audit.json`);
  try {
    const { cmd, args, lockFiles } = buildAuditCommand(tool, yarnVersion);
    const lockDir = await findLockDir(projectPath, lockFiles);
    const cwd = lockDir || projectPath;
    const result = await runCommand(cmd, args, { cwd });
    const parsed = parseJsonOutput(result.stdout);
    const normalized = normalizeAuditOutput(tool, parsed);
    if (normalized) {
      await writeJsonFile(targetFile, normalized);
      return { ok: true, data: normalized, file: targetFile };
    }
    await writeJsonFile(targetFile, { stdout: result.stdout, stderr: result.stderr, code: result.code });
    return { ok: false, error: `Failed to parse ${tool} audit output`, file: targetFile };
  } catch (err: any) {
    await writeJsonFile(targetFile, { error: String(err) });
    return { ok: false, error: `${tool} audit failed: ${String(err)}`, file: targetFile };
  }
}
