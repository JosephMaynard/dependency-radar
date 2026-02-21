import fs from 'fs';
import path from 'path';
import YAML from 'yaml';

export type ResolvedNode = {
  name: string;
  version: string;
  path?: string;
  dependencies?: Record<string, ResolvedNode>;
  dev?: boolean;
};

export type ResolvedTree = {
  dependencies: Record<string, ResolvedNode>;
};

export type LockfileTreeResult = {
  sourceFile: string;
  data: ResolvedTree;
};

type Tool = 'npm' | 'pnpm' | 'yarn';

type PnpmInstallState = {
  enabled: boolean;
  virtualStoreEntries: Set<string>;
  nodeModulesRoots: string[];
  installedCache: Map<string, boolean>;
};

type YarnV1Entry = {
  version?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
};

type YarnV2Entry = {
  version?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
};

const treeCache = new Map<string, LockfileTreeResult | null>();
const parseCache = new Map<string, unknown>();

export async function tryBuildDependencyTreeFromLockfile(
  projectPath: string,
  tool: Tool,
  lockfileSearchRoot?: string
): Promise<LockfileTreeResult | undefined> {
  const searchRoot = path.resolve(lockfileSearchRoot || projectPath);
  const cacheKey = `${tool}:${path.resolve(projectPath)}:${searchRoot}`;
  if (treeCache.has(cacheKey)) {
    const cached = treeCache.get(cacheKey);
    return cached || undefined;
  }

  try {
    let result: LockfileTreeResult | undefined;
    if (tool === 'pnpm') {
      result = parsePnpmTree(projectPath, searchRoot);
    } else if (tool === 'npm') {
      result = parseNpmTree(projectPath, searchRoot);
    } else {
      result = parseYarnTree(projectPath, searchRoot);
    }
    treeCache.set(cacheKey, result || null);
    return result;
  } catch {
    treeCache.set(cacheKey, null);
    return undefined;
  }
}

function parsePnpmTree(projectPath: string, searchRoot: string): LockfileTreeResult | undefined {
  const lockPath = findUpwards(projectPath, ['pnpm-lock.yaml'], searchRoot);
  if (!lockPath) return undefined;
  const parsed = getCachedYaml(lockPath) as {
    importers?: Record<string, any>;
    packages?: Record<string, any>;
    snapshots?: Record<string, any>;
  };
  if (!parsed || typeof parsed !== 'object') return undefined;

  const importers = parsed.importers && typeof parsed.importers === 'object' ? parsed.importers : undefined;
  if (!importers) return undefined;

  const lockDir = path.dirname(lockPath);
  const importerKey = resolvePnpmImporterKey(projectPath, lockDir, importers);
  if (!importerKey) return undefined;
  const importer = importers[importerKey];
  if (!importer || typeof importer !== 'object') return undefined;

  const packageSnapshots = buildPnpmSnapshotMap(parsed.packages, parsed.snapshots);
  const packageIndex = buildPnpmIndex(packageSnapshots);
  const installState = createPnpmInstallState(projectPath);
  const memo = new Map<string, ResolvedNode | undefined>();

  const rootDeps = collectPnpmImporterDependencies(importer);
  const dependencies: Record<string, ResolvedNode> = {};

  for (const [depName, depRef] of Object.entries(rootDeps)) {
    const resolved = resolvePnpmDependency(depName, depRef, packageIndex);
    if (!resolved) continue;
    const node = buildPnpmNode(resolved.packageKey, packageSnapshots, packageIndex, memo, installState, new Set<string>());
    if (node) dependencies[node.name] = node;
  }

  return {
    sourceFile: lockPath,
    data: { dependencies }
  };
}

function resolvePnpmImporterKey(
  projectPath: string,
  lockDir: string,
  importers: Record<string, unknown>
): string | undefined {
  const rel = toPosixRelative(lockDir, projectPath);
  const normalized = rel === '' ? '.' : rel;
  const candidates = [normalized, normalized.replace(/^\.\//, '')];
  if (normalized !== '.') {
    candidates.push(`./${normalized}`);
  }
  for (const candidate of candidates) {
    if (candidate in importers) return candidate;
  }
  if ('.' in importers && normalized === '.') {
    return '.';
  }
  return undefined;
}

function buildPnpmSnapshotMap(
  packages: Record<string, any> | undefined,
  snapshots: Record<string, any> | undefined
): Record<string, any> {
  const out: Record<string, any> = {};
  const keys = new Set<string>([
    ...Object.keys(packages || {}),
    ...Object.keys(snapshots || {})
  ]);

  for (const key of keys) {
    const pkg = packages?.[key];
    const snap = snapshots?.[key];
    out[key] = {
      ...(pkg && typeof pkg === 'object' ? pkg : {}),
      ...(snap && typeof snap === 'object' ? snap : {}),
      dependencies: mergeStringRecord(pkg?.dependencies, snap?.dependencies),
      optionalDependencies: mergeStringRecord(pkg?.optionalDependencies, snap?.optionalDependencies),
      peerDependencies: mergeStringRecord(pkg?.peerDependencies, snap?.peerDependencies)
    };
  }

  return out;
}

function buildPnpmIndex(snapshots: Record<string, any>): {
  byExact: Map<string, string>;
  byStripped: Map<string, string>;
} {
  const byExact = new Map<string, string>();
  const byStripped = new Map<string, string>();

  for (const packageKey of Object.keys(snapshots)) {
    const parsed = parsePnpmPackageKey(packageKey);
    if (!parsed) continue;
    const exact = `${parsed.name}@${parsed.ref}`;
    const stripped = `${parsed.name}@${stripPnpmPeerSuffix(parsed.ref)}`;
    if (!byExact.has(exact)) byExact.set(exact, packageKey);
    if (!byStripped.has(stripped)) byStripped.set(stripped, packageKey);
  }

  return { byExact, byStripped };
}

function collectPnpmImporterDependencies(importer: any): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const section = importer?.[key];
    if (!section || typeof section !== 'object') continue;
    for (const [depName, rawValue] of Object.entries<any>(section)) {
      const ref = extractPnpmRef(rawValue);
      if (!ref) continue;
      if (isWorkspaceLikeSpecifier(ref)) continue;
      out[depName] = ref;
    }
  }
  return out;
}

function resolvePnpmDependency(
  dependencyName: string,
  rawRef: string,
  index: { byExact: Map<string, string>; byStripped: Map<string, string> }
): { packageKey: string } | undefined {
  const normalized = normalizePnpmRef(rawRef, dependencyName);
  if (!normalized) return undefined;

  const exact = `${normalized.name}@${normalized.ref}`;
  const stripped = `${normalized.name}@${stripPnpmPeerSuffix(normalized.ref)}`;
  const packageKey =
    index.byExact.get(exact) ||
    index.byStripped.get(stripped) ||
    (normalized.ref.startsWith('/') ? index.byExact.get(`${normalized.name}@${normalized.ref.slice(1)}`) : undefined);

  if (!packageKey) return undefined;
  return { packageKey };
}

function buildPnpmNode(
  packageKey: string,
  snapshots: Record<string, any>,
  index: { byExact: Map<string, string>; byStripped: Map<string, string> },
  memo: Map<string, ResolvedNode | undefined>,
  installState: PnpmInstallState,
  stack: Set<string>
): ResolvedNode | undefined {
  if (memo.has(packageKey)) return memo.get(packageKey);
  if (stack.has(packageKey)) return undefined;

  const parsedKey = parsePnpmPackageKey(packageKey);
  if (!parsedKey) return undefined;
  const version = extractVersionFromPnpmRef(parsedKey.ref);
  if (!version) return undefined;
  if (!isPnpmPackageInstalled(parsedKey.name, version, installState)) {
    memo.set(packageKey, undefined);
    return undefined;
  }

  const snapshot = snapshots[packageKey] || {};
  const out: ResolvedNode = {
    name: parsedKey.name,
    version,
    dependencies: {}
  };

  stack.add(packageKey);
  const childRefs = mergeStringRecord(
    snapshot?.dependencies,
    mergeStringRecord(snapshot?.optionalDependencies, snapshot?.peerDependencies)
  );

  for (const [childName, childRef] of Object.entries(childRefs)) {
    if (!childRef || isWorkspaceLikeSpecifier(childRef)) continue;
    const resolved = resolvePnpmDependency(childName, childRef, index);
    if (!resolved) continue;
    const childNode = buildPnpmNode(resolved.packageKey, snapshots, index, memo, installState, stack);
    if (!childNode) continue;
    out.dependencies![childNode.name] = childNode;
  }

  stack.delete(packageKey);
  if (out.dependencies && Object.keys(out.dependencies).length === 0) {
    delete out.dependencies;
  }

  memo.set(packageKey, out);
  return out;
}

function parsePnpmPackageKey(key: string): { name: string; ref: string } | undefined {
  const normalized = key.startsWith('/') ? key.slice(1) : key;
  if (!normalized) return undefined;

  if (normalized.startsWith('@')) {
    const slashIndex = normalized.indexOf('/');
    if (slashIndex < 0) return undefined;
    const atIndex = normalized.indexOf('@', slashIndex + 1);
    if (atIndex < 0) return undefined;
    const name = normalized.slice(0, atIndex);
    const ref = normalized.slice(atIndex + 1);
    if (!name || !ref) return undefined;
    return { name, ref };
  }

  const atIndex = normalized.indexOf('@');
  if (atIndex < 0) return undefined;
  const name = normalized.slice(0, atIndex);
  const ref = normalized.slice(atIndex + 1);
  if (!name || !ref) return undefined;
  return { name, ref };
}

function stripPnpmPeerSuffix(ref: string): string {
  return ref.replace(/\(.+\)$/g, '');
}

function extractVersionFromPnpmRef(ref: string): string {
  const stripped = stripPnpmPeerSuffix(ref).trim();
  if (!stripped || isWorkspaceLikeSpecifier(stripped)) return '';
  if (stripped.startsWith('npm:')) {
    const target = stripped.slice(4);
    const at = target.lastIndexOf('@');
    if (at > 0) return target.slice(at + 1);
    return target;
  }
  return stripped;
}

function extractPnpmRef(value: unknown): string | undefined {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed || undefined;
  }
  if (!value || typeof value !== 'object') return undefined;
  const version = (value as { version?: unknown }).version;
  if (typeof version === 'string') {
    const trimmed = version.trim();
    return trimmed || undefined;
  }
  return undefined;
}

function normalizePnpmRef(rawRef: string, dependencyName: string): { name: string; ref: string } | undefined {
  const trimmed = rawRef.trim();
  if (!trimmed || isWorkspaceLikeSpecifier(trimmed)) return undefined;
  if (!trimmed.startsWith('npm:')) {
    const cleaned = trimmed.startsWith('/') ? trimmed.slice(1) : trimmed;
    return { name: dependencyName, ref: cleaned };
  }

  const target = trimmed.slice(4);
  const parsed = parsePackageAliasTarget(target);
  if (!parsed) {
    return { name: dependencyName, ref: target };
  }
  return parsed;
}

function parsePackageAliasTarget(value: string): { name: string; ref: string } | undefined {
  if (!value) return undefined;
  if (value.startsWith('@')) {
    const slashIndex = value.indexOf('/');
    if (slashIndex < 0) return undefined;
    const atIndex = value.indexOf('@', slashIndex + 1);
    if (atIndex < 0) return undefined;
    return {
      name: value.slice(0, atIndex),
      ref: value.slice(atIndex + 1)
    };
  }
  const atIndex = value.lastIndexOf('@');
  if (atIndex <= 0) return undefined;
  return {
    name: value.slice(0, atIndex),
    ref: value.slice(atIndex + 1)
  };
}

function parseNpmTree(projectPath: string, searchRoot: string): LockfileTreeResult | undefined {
  const lockPath = findUpwards(projectPath, ['npm-shrinkwrap.json', 'package-lock.json'], searchRoot);
  if (!lockPath) return undefined;
  const parsed = getCachedJson(lockPath) as any;
  if (!parsed || typeof parsed !== 'object') return undefined;

  if (parsed.packages && typeof parsed.packages === 'object') {
    const data = parseNpmTreeFromPackages(parsed.packages as Record<string, any>, projectPath, path.dirname(lockPath));
    if (!data) return undefined;
    return { sourceFile: lockPath, data };
  }

  if (parsed.dependencies && typeof parsed.dependencies === 'object') {
    const dependencies: Record<string, ResolvedNode> = {};
    for (const [depName, node] of Object.entries<any>(parsed.dependencies)) {
      const normalized = normalizeLegacyNpmNode(depName, node);
      if (normalized) dependencies[depName] = normalized;
    }
    return { sourceFile: lockPath, data: { dependencies } };
  }

  return undefined;
}

function parseNpmTreeFromPackages(
  packages: Record<string, any>,
  projectPath: string,
  lockDir: string
): ResolvedTree | undefined {
  const projectRel = toPosixRelative(lockDir, projectPath);
  const rootKey = projectRel === '' ? '' : projectRel;
  const packageKey = rootKey in packages ? rootKey : '';
  const rootEntry = packages[packageKey];
  if (!rootEntry || typeof rootEntry !== 'object') return undefined;

  const rootDepNames = collectDependencyNames(rootEntry);
  const dependencies: Record<string, ResolvedNode> = {};
  const memo = new Map<string, ResolvedNode | undefined>();
  const stack = new Set<string>();

  for (const depName of rootDepNames) {
    const childKey = resolveNpmPackagePath(packageKey, depName, packages);
    if (!childKey) continue;
    const childNode = buildNpmNodeFromPackages(childKey, depName, packages, memo, stack);
    if (childNode) dependencies[childNode.name] = childNode;
  }

  return { dependencies };
}

function buildNpmNodeFromPackages(
  packageKey: string,
  fallbackName: string,
  packages: Record<string, any>,
  memo: Map<string, ResolvedNode | undefined>,
  stack: Set<string>
): ResolvedNode | undefined {
  if (memo.has(packageKey)) return memo.get(packageKey);
  if (stack.has(packageKey)) return undefined;
  const entry = packages[packageKey];
  if (!entry || typeof entry !== 'object') return undefined;

  if (entry.link === true && typeof entry.resolved === 'string') {
    const linkedKey = normalizeLockPackageKey(entry.resolved);
    if (linkedKey && linkedKey in packages) {
      const linkedNode = buildNpmNodeFromPackages(linkedKey, fallbackName, packages, memo, stack);
      memo.set(packageKey, linkedNode);
      return linkedNode;
    }
  }

  const version = typeof entry.version === 'string' ? entry.version.trim() : '';
  if (!version || version === 'unknown' || version === 'missing' || version === 'invalid') {
    memo.set(packageKey, undefined);
    return undefined;
  }

  const name = typeof entry.name === 'string' && entry.name.trim() ? entry.name.trim() : fallbackName;
  const out: ResolvedNode = {
    name,
    version,
    dependencies: {}
  };
  if (entry?.dev !== undefined) {
    out.dev = Boolean(entry.dev);
  }

  stack.add(packageKey);
  const depNames = collectDependencyNames(entry);
  for (const depName of depNames) {
    const childKey = resolveNpmPackagePath(packageKey, depName, packages);
    if (!childKey) continue;
    const childNode = buildNpmNodeFromPackages(childKey, depName, packages, memo, stack);
    if (!childNode) continue;
    out.dependencies![childNode.name] = childNode;
  }
  stack.delete(packageKey);

  if (out.dependencies && Object.keys(out.dependencies).length === 0) {
    delete out.dependencies;
  }

  memo.set(packageKey, out);
  return out;
}

function normalizeLockPackageKey(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return '';
  return trimmed.replace(/^\.?\//, '').split(path.sep).join('/');
}

function resolveNpmPackagePath(
  fromPackageKey: string,
  depName: string,
  packages: Record<string, any>
): string | undefined {
  const from = fromPackageKey || '';
  let dir = from;

  while (true) {
    const candidate = dir ? `${dir}/node_modules/${depName}` : `node_modules/${depName}`;
    if (candidate in packages) return candidate;
    if (!dir) break;
    const parent = path.posix.dirname(dir);
    dir = parent === '.' ? '' : parent;
  }

  const rootCandidate = `node_modules/${depName}`;
  return rootCandidate in packages ? rootCandidate : undefined;
}

function normalizeLegacyNpmNode(name: string, node: any): ResolvedNode | undefined {
  if (!node || typeof node !== 'object') return undefined;
  if (node.missing || node.extraneous) return undefined;
  const version = typeof node.version === 'string' ? node.version.trim() : '';
  if (!version || version === 'unknown' || version === 'missing' || version === 'invalid') return undefined;

  const out: ResolvedNode = {
    name,
    version,
    dependencies: {}
  };
  if (node?.dependencies && typeof node.dependencies === 'object') {
    for (const [childName, child] of Object.entries<any>(node.dependencies)) {
      const normalized = normalizeLegacyNpmNode(childName, child);
      if (normalized) out.dependencies![childName] = normalized;
    }
  }
  if (node?.dev !== undefined) {
    out.dev = Boolean(node.dev);
  }
  if (out.dependencies && Object.keys(out.dependencies).length === 0) {
    delete out.dependencies;
  }
  return out;
}

function parseYarnTree(projectPath: string, searchRoot: string): LockfileTreeResult | undefined {
  const lockPath = findUpwards(projectPath, ['yarn.lock'], searchRoot);
  if (!lockPath) return undefined;
  const raw = readCachedText(lockPath);
  if (!raw) return undefined;

  const packageJsonPath = path.join(projectPath, 'package.json');
  if (!safePathExists(packageJsonPath)) return undefined;
  const packageJson = readJsonSafe(packageJsonPath);
  if (!packageJson || typeof packageJson !== 'object') return undefined;

  if (/^#\s*yarn lockfile v1/m.test(raw)) {
    const parsed = parseYarnV1(raw);
    if (!parsed) return undefined;
    const data = buildYarnResolvedTree(parsed, packageJson);
    return { sourceFile: lockPath, data };
  }

  const parsedYaml = parseYarnV2(raw);
  if (!parsedYaml) return undefined;
  const data = buildYarnResolvedTree(parsedYaml, packageJson);
  return { sourceFile: lockPath, data };
}

function parseYarnV1(raw: string): Map<string, YarnV1Entry> | undefined {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const lockfile = require('@yarnpkg/lockfile') as {
    parse: (value: string) => { type: string; object?: Record<string, YarnV1Entry> };
  };
  const parsed = lockfile.parse(raw);
  if (!parsed || parsed.type !== 'success' || !parsed.object) return undefined;

  const map = new Map<string, YarnV1Entry>();
  for (const [selectorKey, entry] of Object.entries(parsed.object)) {
    for (const selector of splitSelectors(selectorKey)) {
      if (!map.has(selector)) {
        map.set(selector, entry || {});
      }
    }
  }
  return map;
}

function parseYarnV2(raw: string): Map<string, YarnV2Entry> | undefined {
  const parsed = YAML.parse(raw) as Record<string, any>;
  if (!parsed || typeof parsed !== 'object') return undefined;
  const map = new Map<string, YarnV2Entry>();

  for (const [selectorKey, entry] of Object.entries(parsed)) {
    if (selectorKey === '__metadata') continue;
    if (!entry || typeof entry !== 'object') continue;
    for (const selector of splitSelectors(selectorKey)) {
      if (!map.has(selector)) {
        map.set(selector, entry as YarnV2Entry);
      }
    }
  }
  return map;
}

function buildYarnResolvedTree(
  lockEntries: Map<string, YarnV1Entry | YarnV2Entry>,
  packageJson: any
): ResolvedTree {
  const memo = new Map<string, ResolvedNode | undefined>();
  const stack = new Set<string>();
  const dependencies: Record<string, ResolvedNode> = {};

  const rootDeps = collectPackageJsonDependencySpecs(packageJson);
  for (const [depName, depRange] of Object.entries(rootDeps)) {
    if (isWorkspaceLikeSpecifier(depRange)) continue;
    const selector = resolveYarnSelector(depName, depRange, lockEntries);
    if (!selector) continue;
    const node = buildYarnNode(depName, selector, lockEntries, memo, stack);
    if (node) dependencies[node.name] = node;
  }

  return { dependencies };
}

function buildYarnNode(
  name: string,
  selector: string,
  lockEntries: Map<string, YarnV1Entry | YarnV2Entry>,
  memo: Map<string, ResolvedNode | undefined>,
  stack: Set<string>
): ResolvedNode | undefined {
  const memoKey = `${name}|${selector}`;
  if (memo.has(memoKey)) return memo.get(memoKey);
  if (stack.has(memoKey)) return undefined;

  const entry = lockEntries.get(selector);
  if (!entry || typeof entry !== 'object') return undefined;
  const version = typeof entry.version === 'string' ? entry.version.trim() : '';
  if (!version || version === 'unknown' || version === 'missing' || version === 'invalid') {
    memo.set(memoKey, undefined);
    return undefined;
  }

  const out: ResolvedNode = {
    name,
    version,
    dependencies: {}
  };

  stack.add(memoKey);
  const childDeps = mergeStringRecord(entry.dependencies, entry.optionalDependencies);
  for (const [depName, depRange] of Object.entries(childDeps)) {
    if (!depRange || isWorkspaceLikeSpecifier(depRange)) continue;
    const childSelector = resolveYarnSelector(depName, depRange, lockEntries);
    if (!childSelector) continue;
    const childNode = buildYarnNode(depName, childSelector, lockEntries, memo, stack);
    if (!childNode) continue;
    out.dependencies![childNode.name] = childNode;
  }
  stack.delete(memoKey);

  if (out.dependencies && Object.keys(out.dependencies).length === 0) {
    delete out.dependencies;
  }

  memo.set(memoKey, out);
  return out;
}

function resolveYarnSelector(
  dependencyName: string,
  dependencyRange: string,
  lockEntries: Map<string, YarnV1Entry | YarnV2Entry>
): string | undefined {
  const trimmedRange = dependencyRange.trim();
  const candidates = new Set<string>([
    `${dependencyName}@${trimmedRange}`,
    `${dependencyName}@npm:${trimmedRange}`
  ]);

  if (trimmedRange.startsWith('npm:')) {
    candidates.add(`${dependencyName}@${trimmedRange.slice(4)}`);
  }

  for (const candidate of candidates) {
    if (lockEntries.has(candidate)) return candidate;
  }

  const prefix = `${dependencyName}@`;
  const fallback: string[] = [];
  for (const selector of lockEntries.keys()) {
    if (!selector.startsWith(prefix)) continue;
    if (selector.includes(trimmedRange)) {
      fallback.push(selector);
    }
  }
  if (fallback.length === 1) return fallback[0];
  if (fallback.length > 1) {
    return fallback.sort()[0];
  }

  return undefined;
}

function collectPackageJsonDependencySpecs(pkg: any): Record<string, string> {
  const out: Record<string, string> = {};
  for (const sectionName of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const section = pkg?.[sectionName];
    if (!section || typeof section !== 'object') continue;
    for (const [name, spec] of Object.entries<any>(section)) {
      if (typeof spec !== 'string') continue;
      out[name] = spec;
    }
  }
  return out;
}

function splitSelectors(selectorKey: string): string[] {
  return selectorKey
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
}

function mergeStringRecord(
  first: unknown,
  second: unknown
): Record<string, string> {
  const out: Record<string, string> = {};

  const assign = (value: unknown) => {
    if (!value || typeof value !== 'object') return;
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      if (typeof val === 'string') {
        out[key] = val;
      }
    }
  };

  assign(first);
  assign(second);
  return out;
}

function collectDependencyNames(entry: any): string[] {
  const names = new Set<string>();
  for (const sectionName of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const section = entry?.[sectionName];
    if (!section || typeof section !== 'object') continue;
    for (const name of Object.keys(section)) {
      names.add(name);
    }
  }
  return Array.from(names);
}

function isWorkspaceLikeSpecifier(value: string): boolean {
  const trimmed = value.trim();
  return (
    trimmed.startsWith('link:') ||
    trimmed.startsWith('workspace:') ||
    trimmed.startsWith('file:') ||
    trimmed.startsWith('portal:')
  );
}

function findUpwards(startPath: string, fileNames: string[], stopPath: string): string | undefined {
  const stop = path.resolve(stopPath);
  let current = path.resolve(startPath);
  while (true) {
    for (const fileName of fileNames) {
      const candidate = path.join(current, fileName);
      if (safePathExists(candidate)) {
        return candidate;
      }
    }
    if (current === stop) {
      return undefined;
    }
    const parent = path.dirname(current);
    if (parent === current) return undefined;
    current = parent;
  }
}

function toPosixRelative(fromPath: string, toPath: string): string {
  const relative = path.relative(fromPath, toPath);
  if (!relative || relative === '.') return '';
  return relative.split(path.sep).join('/');
}

function safePathExists(targetPath: string): boolean {
  try {
    return fs.existsSync(targetPath);
  } catch {
    return false;
  }
}

function readCachedText(filePath: string): string | undefined {
  if (parseCache.has(filePath)) {
    const cached = parseCache.get(filePath);
    return typeof cached === 'string' ? cached : undefined;
  }
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    parseCache.set(filePath, raw);
    return raw;
  } catch {
    return undefined;
  }
}

function getCachedJson(filePath: string): unknown {
  const cacheKey = `${filePath}:json`;
  if (parseCache.has(cacheKey)) return parseCache.get(cacheKey);
  const raw = readCachedText(filePath);
  if (!raw) return undefined;
  const parsed = JSON.parse(raw);
  parseCache.set(cacheKey, parsed);
  return parsed;
}

function getCachedYaml(filePath: string): unknown {
  const cacheKey = `${filePath}:yaml`;
  if (parseCache.has(cacheKey)) return parseCache.get(cacheKey);
  const raw = readCachedText(filePath);
  if (!raw) return undefined;
  const parsed = YAML.parse(raw);
  parseCache.set(cacheKey, parsed);
  return parsed;
}

function readJsonSafe(filePath: string): unknown {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function createPnpmInstallState(projectPath: string): PnpmInstallState {
  const nodeModulesRoots = findNodeModulesRoots(projectPath);
  const virtualStoreEntries = new Set<string>();
  for (const root of nodeModulesRoots) {
    const virtualStoreDir = path.join(root, '.pnpm');
    if (!safePathExists(virtualStoreDir)) continue;
    for (const entry of safeReadDirNames(virtualStoreDir)) {
      virtualStoreEntries.add(entry);
    }
  }
  return {
    enabled: virtualStoreEntries.size > 0 || nodeModulesRoots.length > 0,
    virtualStoreEntries,
    nodeModulesRoots,
    installedCache: new Map<string, boolean>()
  };
}

function findNodeModulesRoots(startPath: string): string[] {
  const roots: string[] = [];
  let current = path.resolve(startPath);
  while (true) {
    const candidate = path.join(current, 'node_modules');
    if (safePathExists(candidate)) {
      roots.push(candidate);
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return roots;
}

function safeReadDirNames(dirPath: string): string[] {
  try {
    return fs.readdirSync(dirPath);
  } catch {
    return [];
  }
}

function isPnpmPackageInstalled(name: string, version: string, installState: PnpmInstallState): boolean {
  if (!installState.enabled) return true;
  const cacheKey = `${name}@${version}`;
  const cached = installState.installedCache.get(cacheKey);
  if (cached !== undefined) return cached;

  const normalizedName = normalizeScopedPackageNameForPnpmStore(name);
  const storePrefix = `${normalizedName}@${version}`;
  for (const entry of installState.virtualStoreEntries) {
    if (entry === storePrefix || entry.startsWith(`${storePrefix}_`) || entry.startsWith(`${storePrefix}(`)) {
      installState.installedCache.set(cacheKey, true);
      return true;
    }
  }

  for (const nodeModulesRoot of installState.nodeModulesRoots) {
    const packageDir = path.join(nodeModulesRoot, ...name.split('/'));
    if (safePathExists(packageDir) && packageDirectoryMatchesVersion(packageDir, version)) {
      installState.installedCache.set(cacheKey, true);
      return true;
    }
  }

  installState.installedCache.set(cacheKey, false);
  return false;
}

function normalizeScopedPackageNameForPnpmStore(name: string): string {
  if (!name.startsWith('@')) return name;
  const slashIndex = name.indexOf('/');
  if (slashIndex <= 0) return name;
  return `${name.slice(0, slashIndex)}+${name.slice(slashIndex + 1)}`;
}

function packageDirectoryMatchesVersion(packageDir: string, expectedVersion: string): boolean {
  const pkgJsonPath = path.join(packageDir, 'package.json');
  if (!safePathExists(pkgJsonPath)) return true;
  try {
    const raw = fs.readFileSync(pkgJsonPath, 'utf8');
    const parsed = JSON.parse(raw);
    const version = typeof parsed?.version === 'string' ? parsed.version.trim() : '';
    return !version || version === expectedVersion;
  } catch {
    return true;
  }
}
