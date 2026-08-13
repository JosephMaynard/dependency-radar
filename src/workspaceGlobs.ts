import fsp from 'fs/promises';
import path from 'path';

// Shared workspace-pattern matching for package.json#workspaces and
// pnpm-workspace.yaml globs. Supports the forms those files actually use:
// literal segments, `*` (one segment), `**` (any depth), and `!`-negated
// exclusion patterns. Kept dependency-free like the rest of the CLI.

function normalizePattern(pattern: string): string {
  return pattern
    .trim()
    .replace(/^[.][/\\]/, '')
    .replace(/[/\\]+$/, '')
    .split(/[/\\]+/g)
    .filter(Boolean)
    .join('/');
}

/** Convert one workspace glob into a full-match regex over a relative path. */
export function workspacePatternToRegex(pattern: string): RegExp {
  const segments = normalizePattern(pattern).split('/');
  let body = '^';
  segments.forEach((segment, index) => {
    const isLast = index === segments.length - 1;
    if (segment === '**') {
      // Trailing `**` requires at least one segment below; mid-pattern `**`
      // spans zero or more whole segments (the next literal supplies its own
      // position after the optional group).
      body += isLast ? '.+' : '(?:[^/]+/)*';
      return;
    }
    const literal = segment
      .split('*')
      .map((piece) => piece.replace(/[.+^${}()|[\]\\?]/g, '\\$&'))
      .join('[^/]*');
    body += literal + (isLast ? '' : '/');
  });
  return new RegExp(`${body}$`);
}

export function splitWorkspacePatterns(patterns: string[]): {
  includes: string[];
  excludes: string[];
} {
  const includes: string[] = [];
  const excludes: string[] = [];
  for (const raw of patterns) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    if (trimmed.startsWith('!')) excludes.push(trimmed.slice(1));
    else includes.push(trimmed);
  }
  return { includes, excludes };
}

/** True when relPath (posix separators) is selected by the pattern list. */
export function matchesWorkspacePatterns(patterns: string[], relPath: string): boolean {
  const normalized = normalizePattern(relPath);
  if (!normalized || normalized.startsWith('..')) return false;
  const { includes, excludes } = splitWorkspacePatterns(patterns);
  if (!includes.some((p) => workspacePatternToRegex(p).test(normalized))) return false;
  return !excludes.some((p) => workspacePatternToRegex(p).test(normalized));
}

const WALK_MAX_DEPTH = 8;

async function listDirs(parent: string): Promise<string[]> {
  const entries = await fsp.readdir(parent, { withFileTypes: true }).catch(() => []);
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((name) => name !== 'node_modules' && !name.startsWith('.'));
}

/**
 * Expand a workspace pattern list to matching directories under rootDir.
 * Walks the tree (bounded depth, skipping node_modules and dotfiles) and
 * applies inclusion and `!` exclusion patterns over relative paths, so nested
 * globs like `packages/*&#47;plugins/*` and negations both work.
 */
export async function expandWorkspacePatterns(
  rootDir: string,
  patterns: string[],
): Promise<string[]> {
  const { includes, excludes } = splitWorkspacePatterns(patterns);
  if (includes.length === 0) return [];
  const includeRegexes = includes.map(workspacePatternToRegex);
  const excludeRegexes = excludes.map(workspacePatternToRegex);
  // Literal (glob-free) patterns can match directories the walk skips only
  // when explicitly listed (e.g. hidden dirs); resolve them directly too.
  const out = new Set<string>();
  for (const literal of includes.filter((p) => !p.includes('*'))) {
    const rel = normalizePattern(literal);
    if (!rel || rel.startsWith('..')) continue;
    if (excludeRegexes.some((re) => re.test(rel))) continue;
    const abs = path.resolve(rootDir, rel);
    try {
      const stat = await fsp.stat(abs);
      if (stat.isDirectory()) out.add(abs);
    } catch {
      // Pattern points nowhere — ignore.
    }
  }

  const maxSegments = Math.min(
    WALK_MAX_DEPTH,
    Math.max(
      ...includes.map((p) => {
        const segs = normalizePattern(p).split('/');
        return segs.includes('**') ? WALK_MAX_DEPTH : segs.length;
      }),
      1,
    ),
  );

  const walk = async (dir: string, relSegments: string[]): Promise<void> => {
    if (relSegments.length >= maxSegments) return;
    for (const name of await listDirs(dir)) {
      const childRel = [...relSegments, name];
      const relPath = childRel.join('/');
      const matchesInclude = includeRegexes.some((re) => re.test(relPath));
      const matchesExclude = excludeRegexes.some((re) => re.test(relPath));
      if (matchesInclude && !matchesExclude) {
        out.add(path.join(dir, name));
      }
      await walk(path.join(dir, name), childRel);
    }
  };
  await walk(rootDir, []);
  return Array.from(out).sort();
}

/**
 * Read a directory's workspace patterns: package.json#workspaces (array or
 * `{packages: []}` form) plus pnpm-workspace.yaml `packages:` entries.
 * Returns undefined when the directory declares no workspace configuration.
 */
export async function readWorkspacePatterns(dir: string): Promise<string[] | undefined> {
  const patterns: string[] = [];
  let declared = false;
  try {
    const raw = await fsp.readFile(path.join(dir, 'package.json'), 'utf8');
    const pkg = JSON.parse(raw) as { workspaces?: unknown };
    const ws = pkg?.workspaces;
    if (ws) {
      declared = true;
      if (Array.isArray(ws)) patterns.push(...ws.filter((p): p is string => typeof p === 'string'));
      else if (
        typeof ws === 'object' &&
        Array.isArray((ws as { packages?: unknown }).packages)
      ) {
        patterns.push(
          ...((ws as { packages: unknown[] }).packages.filter(
            (p): p is string => typeof p === 'string',
          )),
        );
      }
    }
  } catch {
    // No package.json or unparsable — fall through to pnpm-workspace.yaml.
  }
  try {
    const raw = await fsp.readFile(path.join(dir, 'pnpm-workspace.yaml'), 'utf8');
    declared = true;
    let inPackages = false;
    for (const line of raw.split(/\r?\n/)) {
      if (/^packages\s*:/.test(line)) {
        inPackages = true;
        continue;
      }
      if (inPackages) {
        const item = line.match(/^\s+-\s*(["']?)(.*?)\1\s*$/);
        if (item) patterns.push(item[2]);
        else if (/^\S/.test(line)) inPackages = false;
      }
    }
  } catch {
    // No pnpm workspace file.
  }
  return declared ? patterns : undefined;
}
