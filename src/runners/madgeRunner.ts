import path from 'path';
import madge from 'madge';
import { ToolResult } from '../types';
import { pathExists, writeJsonFile } from '../utils';

export async function runMadge(projectPath: string, tempDir: string): Promise<ToolResult<any>> {
  const targetFile = path.join(tempDir, 'madge.json');
  try {
    const srcPath = path.join(projectPath, 'src');
    const hasSrc = await pathExists(srcPath);
    const entry = hasSrc ? srcPath : projectPath;
    const result = await madge(entry, {
      baseDir: projectPath,
      includeNpm: true,
      excludeRegExp: [/node_modules/, /dist/, /build/, /coverage/, /.dependency-radar/]
    });
    const graph = await result.obj();
    await writeJsonFile(targetFile, graph);
    return { ok: true, data: graph, file: targetFile };
  } catch (err: any) {
    await writeJsonFile(targetFile, { error: String(err) });
    return { ok: false, error: `madge failed: ${String(err)}`, file: targetFile };
  }
}
