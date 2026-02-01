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

export async function runNpmAudit(projectPath: string, tempDir: string): Promise<ToolResult<any>> {
  const targetFile = path.join(tempDir, 'npm-audit.json');
  try {
    const pnpmLockDir = await findLockDir(projectPath, ['pnpm-lock.yaml']);
    const npmLockDir = pnpmLockDir ? undefined : await findLockDir(projectPath, ['package-lock.json', 'npm-shrinkwrap.json']);
    const tool = pnpmLockDir ? 'pnpm' : 'npm';
    const cwd = pnpmLockDir || npmLockDir || projectPath;
    const result = await runCommand(tool, ['audit', '--json'], { cwd });
    let parsed: any | undefined;
    try {
      parsed = JSON.parse(result.stdout || '{}');
    } catch (err) {
      parsed = undefined;
    }
    if (parsed) {
      await writeJsonFile(targetFile, parsed);
      return { ok: true, data: parsed, file: targetFile };
    }
    await writeJsonFile(targetFile, { stdout: result.stdout, stderr: result.stderr, code: result.code });
    return { ok: false, error: 'Failed to parse npm audit output', file: targetFile };
  } catch (err: any) {
    await writeJsonFile(targetFile, { error: String(err) });
    return { ok: false, error: `npm audit failed: ${String(err)}`, file: targetFile };
  }
}
