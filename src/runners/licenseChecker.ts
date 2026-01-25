import path from 'path';
import { ToolResult } from '../types';
import { findBin, runCommand, writeJsonFile } from '../utils';

export async function runLicenseChecker(projectPath: string, tempDir: string): Promise<ToolResult<any>> {
  const targetFile = path.join(tempDir, 'license-checker.json');
  const bin = findBin(projectPath, 'license-checker');
  try {
    const result = await runCommand(bin, ['--json'], { cwd: projectPath });
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
    const error = result.code && result.code !== 0 ? `license-checker exited with code ${result.code}` : 'Failed to parse license-checker output';
    return { ok: false, error, file: targetFile };
  } catch (err: any) {
    await writeJsonFile(targetFile, { error: String(err) });
    return { ok: false, error: `license-checker failed: ${String(err)}`, file: targetFile };
  }
}
