import path from 'path';
import { ToolResult } from '../types';
import { runCommand, writeJsonFile } from '../utils';

export async function runNpmAudit(projectPath: string, tempDir: string): Promise<ToolResult<any>> {
  const targetFile = path.join(tempDir, 'npm-audit.json');
  try {
    const result = await runCommand('npm', ['audit', '--json'], { cwd: projectPath });
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
