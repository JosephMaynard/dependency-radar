import path from 'path';
import fsp from 'fs/promises';
import { ToolResult } from '../types';
import { pathExists, writeJsonFile } from '../utils';

const IGNORED_DIRS = new Set(['node_modules', 'dist', 'build', 'coverage', '.dependency-radar']);
const SOURCE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];

export async function runImportGraph(projectPath: string, tempDir: string): Promise<ToolResult<any>> {
  const targetFile = path.join(tempDir, 'import-graph.json');
  try {
    const srcPath = path.join(projectPath, 'src');
    const hasSrc = await pathExists(srcPath);
    const entry = hasSrc ? srcPath : projectPath;
    const files = await collectSourceFiles(entry);
    const graph: Record<string, string[]> = {};

    for (const file of files) {
      const rel = normalizePath(projectPath, file);
      const content = await fsp.readFile(file, 'utf8');
      const imports = extractImports(content);
      const resolved = await resolveImports(imports, path.dirname(file), projectPath);
      graph[rel] = resolved;
    }

    await writeJsonFile(targetFile, graph);
    return { ok: true, data: graph, file: targetFile };
  } catch (err: any) {
    await writeJsonFile(targetFile, { error: String(err) });
    return { ok: false, error: `import graph failed: ${String(err)}`, file: targetFile };
  }
}

async function collectSourceFiles(rootDir: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(current: string): Promise<void> {
    const entries = await fsp.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        await walk(fullPath);
      } else if (entry.isFile()) {
        if (SOURCE_EXTENSIONS.includes(path.extname(entry.name))) {
          files.push(fullPath);
        }
      }
    }
  }

  await walk(rootDir);
  return files;
}

function extractImports(content: string): string[] {
  const matches = new Set<string>();
  const patterns = [
    /\bimport\s+(?:[^'"]+from\s+)?['"]([^'"]+)['"]/g,
    /\bexport\s+(?:[^'"]+from\s+)?['"]([^'"]+)['"]/g,
    /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\bimport\(\s*['"]([^'"]+)['"]\s*\)/g
  ];

  for (const pattern of patterns) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      if (match[1]) matches.add(match[1]);
    }
  }

  return Array.from(matches);
}

async function resolveImports(specifiers: string[], fileDir: string, projectPath: string): Promise<string[]> {
  const resolved: string[] = [];
  for (const spec of specifiers) {
    if (spec.startsWith('.') || spec.startsWith('/')) {
      const target = await resolveFileTarget(spec, fileDir, projectPath);
      if (target) resolved.push(target);
    } else {
      resolved.push(toPackageName(spec));
    }
  }
  return resolved;
}

async function resolveFileTarget(spec: string, fileDir: string, projectPath: string): Promise<string | undefined> {
  const base = spec.startsWith('/')
    ? path.resolve(projectPath, `.${spec}`)
    : path.resolve(fileDir, spec);
  const direct = await resolveFile(base);
  if (direct) return normalizePath(projectPath, direct);
  return normalizePath(projectPath, base);
}

async function resolveFile(basePath: string): Promise<string | undefined> {
  if (await isFile(basePath)) return basePath;
  for (const ext of SOURCE_EXTENSIONS) {
    const candidate = `${basePath}${ext}`;
    if (await isFile(candidate)) return candidate;
  }
  if (await isDir(basePath)) {
    for (const ext of SOURCE_EXTENSIONS) {
      const candidate = path.join(basePath, `index${ext}`);
      if (await isFile(candidate)) return candidate;
    }
  }
  return undefined;
}

async function isFile(target: string): Promise<boolean> {
  try {
    const stat = await fsp.stat(target);
    return stat.isFile();
  } catch {
    return false;
  }
}

async function isDir(target: string): Promise<boolean> {
  try {
    const stat = await fsp.stat(target);
    return stat.isDirectory();
  } catch {
    return false;
  }
}

function toPackageName(spec: string): string {
  if (spec.startsWith('@')) {
    const parts = spec.split('/');
    return parts.slice(0, 2).join('/');
  }
  return spec.split('/')[0];
}

function normalizePath(baseDir: string, filePath: string): string {
  const rel = path.relative(baseDir, filePath);
  return rel.split(path.sep).join('/');
}
