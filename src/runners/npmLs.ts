import path from 'path';
import { ToolResult } from '../types';
import { runCommand, writeJsonFile } from '../utils';

export async function runNpmLs(projectPath: string, tempDir: string): Promise<ToolResult<any>> {
  const targetFile = path.join(tempDir, 'npm-ls.json');
  try {
    const result = await runCommand('npm', ['ls', '--json', '--all'], { cwd: projectPath });
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
    const error = result.code && result.code !== 0 ? `npm ls exited with code ${result.code}` : 'Failed to parse npm ls output';
    return { ok: false, error, file: targetFile };
  } catch (err: any) {
    await writeJsonFile(targetFile, { error: String(err) });
    return { ok: false, error: `npm ls failed: ${String(err)}`, file: targetFile };
  }
}
