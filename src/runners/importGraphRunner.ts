import path from 'path';
import fsp from 'fs/promises';
import { builtinModules } from 'module';
import { ToolResult } from '../types';
import { writeJsonFile } from '../utils';

const IGNORED_DIRS = new Set([
  'node_modules',
  'dist',
  'build',
  'coverage',
  'storybook-static',
  '.dependency-radar'
]);
const SOURCE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];

/**
 * Builds an import graph for a project and optionally writes it to disk.
 *
 * The produced graph maps each project-relative source file to its resolved local file dependencies,
 * referenced packages, per-file package usage counts, and any unresolved import specifiers.
 *
 * @param options - Optional settings.
 * @param options.persistToDisk - When `false`, the graph is not written to disk; defaults to `true`.
 * @returns An object with:
 *  - `ok: true` and `data` containing `{ files, packages, packageCounts, unresolvedImports }` on success.
 *    When the graph was persisted to disk, a `file` field points to the written JSON file (`<tempDir>/import-graph.json`).
 *  - `ok: false` and `error` containing an error message on failure. If persistence was enabled, a `file` field may point to
 *    the JSON file containing the error object.
 */
export async function runImportGraph(
  projectPath: string,
  tempDir: string,
  options: { persistToDisk?: boolean } = {}
): Promise<ToolResult<any>> {
  const persistToDisk = options.persistToDisk !== false;
  const targetFile = path.join(tempDir, 'import-graph.json');
  try {
    const files = await collectSourceFiles(projectPath);
    const fileGraph: Record<string, string[]> = {};
    const packageGraph: Record<string, string[]> = {};
    const packageCounts: Record<string, Record<string, number>> = {};
    const unresolvedImports: Array<{ importer: string; specifier: string }> = [];

    for (const file of files) {
      const rel = normalizePath(projectPath, file);
      const content = await fsp.readFile(file, 'utf8');
      const imports = extractImports(content);
      const resolved = await resolveImports(imports, path.dirname(file), projectPath);
      fileGraph[rel] = resolved.files;
      packageGraph[rel] = resolved.packages;
      packageCounts[rel] = resolved.packageCounts;
      unresolvedImports.push(...resolved.unresolved.map((spec) => ({ importer: rel, specifier: spec })));
    }

    const output = { files: fileGraph, packages: packageGraph, packageCounts, unresolvedImports };
    if (persistToDisk) {
      await writeJsonFile(targetFile, output);
    }
    return { ok: true, data: output, ...(persistToDisk ? { file: targetFile } : {}) };
  } catch (err: any) {
    if (persistToDisk) {
      await writeJsonFile(targetFile, { error: String(err) });
    }
    return {
      ok: false,
      error: `import graph failed: ${String(err)}`,
      ...(persistToDisk ? { file: targetFile } : {})
    };
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

/**
 * Blank out comments so import-looking text inside them can't register as
 * evidence. Regex literals are recognised with the standard preceding-token
 * heuristic so `/[/*]/` or `://` inside them are not mistaken for comments;
 * string literals are left alone (the import patterns demand surrounding
 * syntax anyway). Positions are preserved (comments become spaces). If a
 * block comment is unterminated the original content is returned unchanged —
 * failing open to the old behaviour beats blanking a file to EOF.
 */
function stripComments(content: string): string {
  let out = '';
  let i = 0;
  let quote: string | undefined;
  let escaped = false;
  let maskStrings = false;
  // Last non-whitespace character emitted outside strings/comments; a '/'
  // after one of these starts a regex literal, not division.
  let prevSignificant = '';
  const regexPreceders = new Set([
    '', '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '<', '>', '+', '-', '*', '%', '~', '^',
  ]);
  while (i < content.length) {
    const ch = content[i];
    const next = content[i + 1];
    if (quote) {
      if (escaped) {
        escaped = false;
        out += maskStrings ? ' ' : ch;
      } else if (ch === '\\') {
        escaped = true;
        out += maskStrings ? ' ' : ch;
      } else if (ch === quote) {
        quote = undefined;
        out += ch;
      } else {
        // Inside a non-specifier string: blank the content so text like
        // "require('ghost-pkg')" in documentation strings can't register
        // as import evidence. Newlines survive so positions keep meaning.
        out += maskStrings && ch !== '\n' ? ' ' : ch;
      }
      i += 1;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      // Only strings sitting in import-specifier position keep their
      // contents: after `from`, `import`/`import(`, `export`, `require(`.
      // Template literals are never specifiers. Test just the tail — an
      // end-anchored regex over the whole accumulator goes quadratic on
      // large files.
      maskStrings =
        ch === '`' ||
        !/(?:\bfrom|\bimport|\bexport|\brequire\s*\(|\bimport\s*\()\s*$/.test(
          out.slice(-24),
        );
      out += ch;
      prevSignificant = ch;
      i += 1;
      continue;
    }
    if (ch === '/' && (next === '/' || next === '*') ) {
      if (next === '/') {
        while (i < content.length && content[i] !== '\n') {
          out += ' ';
          i += 1;
        }
        continue;
      }
      const close = content.indexOf('*/', i + 2);
      if (close === -1) return content; // unterminated — fail open
      for (let j = i; j < close + 2; j += 1) {
        out += content[j] === '\n' ? '\n' : ' ';
      }
      i = close + 2;
      continue;
    }
    if (ch === '/' && regexPreceders.has(prevSignificant)) {
      // Consume a regex literal (with character classes) verbatim.
      out += ch;
      i += 1;
      let inClass = false;
      let regexEscaped = false;
      while (i < content.length) {
        const rc = content[i];
        out += rc;
        i += 1;
        if (regexEscaped) {
          regexEscaped = false;
          continue;
        }
        if (rc === '\\') {
          regexEscaped = true;
          continue;
        }
        if (rc === '[') inClass = true;
        else if (rc === ']') inClass = false;
        else if (rc === '/' && !inClass) break;
        else if (rc === '\n') break; // not actually a regex — bail out
      }
      prevSignificant = '/';
      continue;
    }
    out += ch;
    if (!/\s/.test(ch)) prevSignificant = ch;
    i += 1;
  }
  return out;
}

/** True for type-only import/export statements, erased at compile time. */
function isTypeOnlyStatement(matchedText: string): boolean {
  return /^(?:import|export)\s+type[\s{*]/.test(matchedText);
}

export function extractImports(content: string): string[] {
  const matches: string[] = [];
  const stripped = stripComments(content);
  const patterns = [
    /\bimport\s+(?:[^'"]+from\s+)?['"]([^'"]+)['"]/g,
    /\bexport\s+(?:[^'"]+from\s+)?['"]([^'"]+)['"]/g,
    /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\bimport\(\s*['"]([^'"]+)['"]\s*\)/g
  ];

  for (const pattern of patterns) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(stripped)) !== null) {
      // Type-only imports/exports never load the package at runtime; checking
      // the matched statement itself (not a precomputed span) keeps the
      // exclusion from bleeding across statement boundaries.
      if (match[1] && !isTypeOnlyStatement(match[0])) matches.push(match[1]);
    }
  }

  return matches;
}

async function resolveImports(
  specifiers: string[],
  fileDir: string,
  projectPath: string
): Promise<{ files: string[]; packages: string[]; packageCounts: Record<string, number>; unresolved: string[] }> {
  const resolvedFiles: string[] = [];
  const resolvedPackages: string[] = [];
  const packageCounts: Record<string, number> = {};
  const unresolved: string[] = [];
  for (const spec of specifiers) {
    if (isBuiltinModule(spec)) continue;
    if (spec.startsWith('.') || spec.startsWith('/')) {
      const target = await resolveFileTarget(spec, fileDir, projectPath);
      if (target) {
        resolvedFiles.push(target);
      } else {
        unresolved.push(spec);
      }
    } else {
      const pkgName = toPackageName(spec);
      resolvedPackages.push(pkgName);
      packageCounts[pkgName] = (packageCounts[pkgName] || 0) + 1;
    }
  }
  return {
    files: uniqSorted(resolvedFiles),
    packages: uniqSorted(resolvedPackages),
    packageCounts,
    unresolved: uniqSorted(unresolved)
  };
}

async function resolveFileTarget(spec: string, fileDir: string, projectPath: string): Promise<string | undefined> {
  const base = spec.startsWith('/')
    ? path.resolve(projectPath, `.${spec}`)
    : path.resolve(fileDir, spec);
  const direct = await resolveFile(base);
  if (direct) return normalizePath(projectPath, direct);
  return undefined;
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

const BUILTIN_MODULES = new Set(
  builtinModules.flatMap((mod) => (mod.startsWith('node:') ? [mod, mod.slice(5)] : [mod]))
);

function isBuiltinModule(spec: string): boolean {
  const normalized = spec.startsWith('node:') ? spec.slice(5) : spec;
  if (BUILTIN_MODULES.has(spec) || BUILTIN_MODULES.has(normalized)) return true;
  const root = normalized.split('/')[0];
  return BUILTIN_MODULES.has(root);
}

function uniqSorted(values: string[]): string[] {
  return Array.from(new Set(values)).sort();
}
