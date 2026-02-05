import path from 'path';
import { ToolResult } from '../types';
import { runCommand, writeJsonFile } from '../utils';

type ResolvedNode = {
  name: string;
  version: string;
  path?: string;
  dependencies?: Record<string, ResolvedNode>;
  dev?: boolean;
};

type ResolvedTree = {
  dependencies: Record<string, ResolvedNode>;
};

const PNPM_DEPTH_ATTEMPTS = ['Infinity', '8', '4', '2', '1'];
const PNPM_MAX_OLD_SPACE_SIZE_MB = '8192';

// Normalize package-manager-specific list output into a shared dependency tree.
export async function runNpmLs(projectPath: string, tempDir: string, tool: 'npm' | 'pnpm' | 'yarn' = 'npm'): Promise<ToolResult<any>> {
  const targetFile = path.join(tempDir, `${tool}-ls.json`);
  try {
    if (tool === 'pnpm') {
      return await runPnpmLsWithFallback(projectPath, targetFile);
    }
    const { args, normalize } = buildLsCommand(tool);
    const result = await runCommand(tool, args, { cwd: projectPath });
    const parsed = parseJsonOutput(result.stdout);
    const normalized = normalize(parsed);
    if (normalized) {
      await writeJsonFile(targetFile, normalized);
      return { ok: true, data: normalized, file: targetFile };
    }
    await writeJsonFile(targetFile, { stdout: result.stdout, stderr: result.stderr, code: result.code });
    const error = buildLsFailureMessage(tool, result.code, result.stderr);
    return { ok: false, error, file: targetFile };
  } catch (err: any) {
    await writeJsonFile(targetFile, { error: String(err) });
    return { ok: false, error: `${tool} ls failed: ${String(err)}`, file: targetFile };
  }
}

function buildLsCommand(tool: 'npm' | 'pnpm' | 'yarn'): { args: string[]; normalize: (data: any) => ResolvedTree | undefined } {
  if (tool === 'yarn') {
    return {
      args: ['list', '--json', '--depth', 'Infinity'],
      normalize: normalizeYarnTree
    };
  }
  return {
    args: ['ls', '--json', '--all', '--long'],
    normalize: normalizeNpmTree
  };
}

async function runPnpmLsWithFallback(projectPath: string, targetFile: string): Promise<ToolResult<any>> {
  const normalize = normalizePnpmTree;
  const attempts: Array<{
    depth: string;
    code: number | null;
    stdoutBytes: number;
    stderrPreview: string;
    outOfMemory: boolean;
  }> = [];
  const env = {
    NODE_OPTIONS: ensureNodeMaxOldSpaceSize(process.env.NODE_OPTIONS, PNPM_MAX_OLD_SPACE_SIZE_MB)
  };

  for (const depth of PNPM_DEPTH_ATTEMPTS) {
    const result = await runCommand('pnpm', ['list', '--json', '--depth', depth], {
      cwd: projectPath,
      env
    });
    const parsed = parseJsonOutput(result.stdout);
    const normalized = normalize(parsed);
    const outOfMemory = isOutOfMemoryError(result.stderr);
    attempts.push({
      depth,
      code: result.code,
      stdoutBytes: Buffer.byteLength(result.stdout || '', 'utf8'),
      stderrPreview: trimText(result.stderr, 1200),
      outOfMemory
    });
    if (normalized) {
      await writeJsonFile(targetFile, normalized);
      return { ok: true, data: normalized, file: targetFile };
    }
  }

  await writeJsonFile(targetFile, {
    error: 'pnpm ls retries exhausted',
    nodeOptions: env.NODE_OPTIONS,
    attempts
  });

  const sawOom = attempts.some((attempt) => attempt.outOfMemory);
  const lastAttempt = attempts[attempts.length - 1];
  if (sawOom) {
    return {
      ok: false,
      error: 'pnpm ls ran out of memory while building the dependency tree (retried with lower depths).',
      file: targetFile
    };
  }
  const suffix = lastAttempt && typeof lastAttempt.code === 'number'
    ? ` Last exit code: ${lastAttempt.code}.`
    : '';
  return {
    ok: false,
    error: `Failed to parse pnpm ls output after retries.${suffix}`,
    file: targetFile
  };
}

function ensureNodeMaxOldSpaceSize(existing: string | undefined, megabytes: string): string {
  const token = '--max-old-space-size=';
  if (typeof existing === 'string' && existing.includes(token)) {
    return existing;
  }
  const option = `${token}${megabytes}`;
  return existing && existing.trim() ? `${existing.trim()} ${option}` : option;
}

function isOutOfMemoryError(stderr: string): boolean {
  return /heap out of memory|Reached heap limit|Allocation failed - JavaScript heap out of memory/i.test(stderr || '');
}

function trimText(text: string, maxChars: number): string {
  if (!text) return '';
  const trimmed = text.trim();
  if (trimmed.length <= maxChars) return trimmed;
  return trimmed.slice(trimmed.length - maxChars);
}

function buildLsFailureMessage(tool: 'npm' | 'pnpm' | 'yarn', code: number | null, stderr: string): string {
  if (isOutOfMemoryError(stderr)) {
    return `${tool} ls ran out of memory while building the dependency tree`;
  }
  if (typeof code === 'number' && code !== 0) {
    return `${tool} ls exited with code ${code}`;
  }
  if (code === null && stderr && stderr.trim()) {
    return `${tool} ls failed before completion`;
  }
  return `Failed to parse ${tool} ls output`;
}

function parseJsonOutput(raw: string): any {
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    // Some tools emit JSONL (yarn). Parse best-effort into an array of objects.
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

function normalizeNpmTree(data: any): ResolvedTree | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const deps = data.dependencies && typeof data.dependencies === 'object' ? data.dependencies : {};
  const normalized: ResolvedTree = { dependencies: {} };
  for (const [name, node] of Object.entries<any>(deps)) {
    const normalizedNode = normalizeNpmNode(name, node);
    if (normalizedNode) normalized.dependencies[name] = normalizedNode;
  }
  return normalized;
}

function normalizeNpmNode(name: string, node: any): ResolvedNode | undefined {
  if (!node || typeof node !== 'object') return undefined;
  if (node.missing || node.extraneous) return undefined;
  const version = typeof node?.version === 'string' ? node.version.trim() : '';
  if (!version || version === 'unknown' || version === 'missing' || version === 'invalid') return undefined;
  const out: ResolvedNode = { name, version, dependencies: {} };
  if (typeof node.path === 'string' && node.path.trim()) {
    out.path = node.path.trim();
  }
  if (node?.dependencies && typeof node.dependencies === 'object') {
    for (const [childName, child] of Object.entries<any>(node.dependencies)) {
      const normalizedChild = normalizeNpmNode(childName, child);
      if (normalizedChild) out.dependencies![childName] = normalizedChild;
    }
  }
  if (node?.dev !== undefined) out.dev = Boolean(node.dev);
  if (out.dependencies && Object.keys(out.dependencies).length === 0) {
    delete out.dependencies;
  }
  return out;
}

function normalizePnpmTree(data: any): ResolvedTree | undefined {
  const roots = Array.isArray(data) ? data : [data];
  const root = roots.find((entry) => entry && typeof entry === 'object');
  if (!root || typeof root !== 'object') return undefined;
  const dependencies = collectPnpmDependencyMap(root);
  return { dependencies };
}

function collectPnpmDependencyMap(node: any): Record<string, ResolvedNode> {
  const out: Record<string, ResolvedNode> = {};
  const groups = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
  for (const group of groups) {
    const value = node?.[group];
    if (!value) continue;
    if (Array.isArray(value)) {
      for (const entry of value) {
        if (!entry || typeof entry !== 'object') continue;
        const name = typeof entry.name === 'string' ? entry.name : undefined;
        if (!name) continue;
        const normalized = normalizePnpmNode(name, entry);
        if (normalized) out[name] = normalized;
      }
      continue;
    }
    if (typeof value === 'object') {
      for (const [name, entry] of Object.entries<any>(value)) {
        if (!entry || typeof entry !== 'object') continue;
        const normalized = normalizePnpmNode(name, entry);
        if (normalized) out[name] = normalized;
      }
    }
  }
  if (Object.keys(out).length > 0) return out;
  if (node?.dependencies && typeof node.dependencies === 'object') {
    for (const [name, entry] of Object.entries<any>(node.dependencies)) {
      const normalized = normalizePnpmNode(name, entry);
      if (normalized) out[name] = normalized;
    }
  }
  return out;
}

function normalizePnpmNode(name: string, node: any): ResolvedNode | undefined {
  const version = typeof node?.version === 'string' ? node.version.trim() : '';
  if (!version || version === 'unknown' || version === 'missing' || version === 'invalid') return undefined;
  const out: ResolvedNode = { name, version, dependencies: {} };
  const childMap = collectPnpmDependencyMap(node);
  if (Object.keys(childMap).length > 0) {
    out.dependencies = childMap;
  } else {
    delete out.dependencies;
  }
  if (node?.dev !== undefined) out.dev = Boolean(node.dev);
  return out;
}

function normalizeYarnTree(data: any): ResolvedTree | undefined {
  const treePayload = resolveYarnTreePayload(data);
  if (!treePayload || !Array.isArray(treePayload.trees)) return undefined;
  const out: ResolvedTree = { dependencies: {} };
  for (const node of treePayload.trees) {
    const parsed = normalizeYarnNode(node);
    if (parsed) out.dependencies[parsed.name] = parsed.node;
  }
  return out;
}

function resolveYarnTreePayload(data: any): any | undefined {
  if (!data) return undefined;
  if (data?.data?.trees) return data.data;
  if (data?.trees) return data;
  if (Array.isArray(data)) {
    const treeItem = data.find((item) => item && typeof item === 'object' && item.type === 'tree' && item.data?.trees);
    return treeItem?.data;
  }
  return undefined;
}

function normalizeYarnNode(node: any): { name: string; node: ResolvedNode } | undefined {
  if (!node || typeof node !== 'object') return undefined;
  const label = typeof node.name === 'string' ? node.name : '';
  const parsed = splitYarnLabel(label);
  if (!parsed.version || parsed.version === 'unknown' || parsed.version === 'missing' || parsed.version === 'invalid') return undefined;
  const out: ResolvedNode = { name: parsed.name, version: parsed.version, dependencies: {} };
  if (Array.isArray(node.children)) {
    for (const child of node.children) {
      const parsedChild = normalizeYarnNode(child);
      if (parsedChild) {
        out.dependencies![parsedChild.name] = parsedChild.node;
      }
    }
  }
  if (out.dependencies && Object.keys(out.dependencies).length === 0) {
    delete out.dependencies;
  }
  return { name: parsed.name, node: out };
}

function splitYarnLabel(label: string): { name: string; version: string } {
  if (!label) return { name: 'unknown', version: 'unknown' };
  const lastAt = label.lastIndexOf('@');
  if (lastAt <= 0) return { name: label, version: 'unknown' };
  const name = label.slice(0, lastAt);
  let version = label.slice(lastAt + 1);
  if (version.startsWith('npm:')) {
    version = version.slice(4);
  }
  return { name, version: version || 'unknown' };
}
