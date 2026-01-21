import path from 'path';
import depcheck from 'depcheck';
import { ToolResult } from '../types';
import { writeJsonFile } from '../utils';

export async function runDepcheck(projectPath: string, tempDir: string): Promise<ToolResult<any>> {
  const targetFile = path.join(tempDir, 'depcheck.json');
  try {
    const result = await depcheck(projectPath, {
      ignoreDirs: ['.dependency-radar', 'dist', 'build', 'coverage', 'node_modules']
    });
    await writeJsonFile(targetFile, result);
    return { ok: true, data: result, file: targetFile };
  } catch (err: any) {
    await writeJsonFile(targetFile, { error: String(err) });
    return { ok: false, error: `depcheck failed: ${String(err)}`, file: targetFile };
  }
}
