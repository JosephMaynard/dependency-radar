#!/usr/bin/env node
import path from "path";
import { ChildProcess, spawn } from "child_process";
import { platform } from "os";
import { aggregateData } from "./aggregator";
import { runImportGraph } from "./runners/importGraphRunner";
import { runPackageAudit } from "./runners/npmAudit";
import { runNpmLs } from "./runners/npmLs";
import { runPackageOutdated } from "./runners/npmOutdated";
import { renderReport } from "./report";
import type {
  AggregatedData,
  OutdatedEntry,
  OutdatedResult,
  ToolResult,
  WorkspacePackage,
} from "./types";
import fs from "fs/promises";
import { ensureDir, removeDir, runCommand, pathExists } from "./utils";

// Workspace detection and helpers
type WorkspaceType = "pnpm" | "npm" | "yarn" | "none";
type PackageManager = "npm" | "pnpm" | "yarn";

interface WorkspaceDiscovery {
  type: WorkspaceType;
  packagePaths: string[]; // absolute paths
  pnpmWorkspaceOverrides?: Record<string, unknown>;
}

type OutdatedAttempt = {
  attempted: boolean;
  result?: ToolResult<any>;
};

type WorkspacePackageMeta = { path: string; name: string; pkg: any };

type ParsedYamlLine = {
  indent: number;
  content: string;
};

function normalizeSlashes(p: string): string {
  return p.split(path.sep).join("/");
}

function isCI(): boolean {
  return Boolean(
    process.env.CI === "true" ||
    process.env.CI === "TRUE" ||
    process.env.CI === "1" ||
    process.env.GITHUB_ACTIONS ||
    process.env.GITLAB_CI ||
    process.env.CIRCLECI ||
    process.env.JENKINS_URL ||
    process.env.BUILDKITE,
  );
}

async function listDirs(parent: string): Promise<string[]> {
  const entries = await fs
    .readdir(parent, { withFileTypes: true })
    .catch(() => [] as any);
  return (entries as any[])
    .filter((e: any) => e?.isDirectory?.())
    .map((e: any) => path.join(parent, e.name));
}

async function expandWorkspacePattern(
  root: string,
  pattern: string,
): Promise<string[]> {
  // Minimal glob support for common workspaces:
  // - "packages/*", "apps/*"
  // - "packages/**" (recursive)
  // - "./packages/*" (leading ./)
  const cleaned = pattern.trim().replace(/^[.][/\\]/, "");
  if (!cleaned) return [];

  // Disallow node_modules and hidden by default
  const parts = cleaned.split(/[/\\]/g).filter(Boolean);
  const isRecursive = parts.includes("**");

  // Find the segment containing * or **
  const starIndex = parts.findIndex((p) => p === "*" || p === "**");

  if (starIndex === -1) {
    const abs = path.resolve(root, cleaned);
    return (await pathExists(abs)) ? [abs] : [];
  }

  const baseParts = parts.slice(0, starIndex);
  const baseDir = path.resolve(root, baseParts.join(path.sep));
  if (!(await pathExists(baseDir))) return [];

  if (parts[starIndex] === "*" && starIndex === parts.length - 1) {
    // one-level children
    return await listDirs(baseDir);
  }

  if (parts[starIndex] === "**") {
    // recursive directories under base
    const out: string[] = [];
    async function walk(dir: string): Promise<void> {
      const children = await listDirs(dir);
      for (const child of children) {
        if (path.basename(child) === "node_modules") continue;
        if (path.basename(child).startsWith(".")) continue;
        out.push(child);
        await walk(child);
      }
    }
    await walk(baseDir);
    return out;
  }

  // Fallback: treat as one-level
  return await listDirs(baseDir);
}

async function readJsonFile(filePath: string): Promise<any | undefined> {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function stripYamlInlineComment(rawLine: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < rawLine.length; i += 1) {
    const ch = rawLine[i];
    const prev = i > 0 ? rawLine[i - 1] : "";
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle && prev !== "\\") {
      inDouble = !inDouble;
      continue;
    }
    if (ch === "#" && !inSingle && !inDouble) {
      return rawLine.slice(0, i);
    }
  }
  return rawLine;
}

function unquoteYamlScalar(value: string): string {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    const quote = trimmed[0];
    const inner = trimmed.slice(1, -1);
    return quote === '"'
      ? inner
          .replace(/\\"/g, '"')
          .replace(/\\\\/g, "\\")
      : inner.replace(/''/g, "'");
  }
  return trimmed;
}

function parseYamlScalar(value: string): unknown {
  const normalized = value.trim();
  if (!normalized) return "";
  if (normalized === "{}") return {};
  if (normalized === "[]") return [];
  if (normalized === "null" || normalized === "~") return null;
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  return unquoteYamlScalar(normalized);
}

function findYamlMapSeparator(content: string): number {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < content.length; i += 1) {
    const ch = content[i];
    const prev = i > 0 ? content[i - 1] : "";
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle && prev !== "\\") {
      inDouble = !inDouble;
      continue;
    }
    if (ch !== ":" || inSingle || inDouble) continue;
    const next = content[i + 1];
    if (next === undefined || next === " " || next === "\t") {
      return i;
    }
  }
  return -1;
}

function toObjectRecord(
  value: unknown,
): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function mergeRecordObjects(
  ...objects: Array<Record<string, unknown> | undefined>
): Record<string, unknown> | undefined {
  const merged: Record<string, unknown> = {};
  for (const obj of objects) {
    if (!obj) continue;
    for (const [key, val] of Object.entries(obj)) {
      merged[key] = val;
    }
  }
  return Object.keys(merged).length > 0 ? merged : undefined;
}

function normalizeStringArray(value: unknown): string[] {
  if (typeof value === "string") {
    const single = value.trim();
    return single ? [single] : [];
  }
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
    .filter(Boolean);
}

function parseSimpleYaml(yaml: string): Record<string, unknown> {
  const lines: ParsedYamlLine[] = [];
  for (const rawLine of yaml.split(/\r?\n/)) {
    const noComment = stripYamlInlineComment(rawLine).replace(/\s+$/, "");
    if (!noComment.trim()) continue;
    const indent = noComment.match(/^(\s*)/)?.[1].length ?? 0;
    lines.push({
      indent,
      content: noComment.trim(),
    });
  }

  let index = 0;

  const parseNode = (indentLevel: number): unknown => {
    if (index >= lines.length) return undefined;
    if (lines[index].indent < indentLevel) return undefined;
    if (
      lines[index].indent === indentLevel &&
      lines[index].content.startsWith("- ")
    ) {
      return parseSequence(indentLevel);
    }
    return parseMapping(indentLevel);
  };

  const parseMapping = (indentLevel: number): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    while (index < lines.length) {
      const line = lines[index];
      if (line.indent < indentLevel) break;
      if (line.indent > indentLevel) {
        index += 1;
        continue;
      }
      if (line.content.startsWith("- ")) break;
      const colonIndex = findYamlMapSeparator(line.content);
      if (colonIndex <= 0) {
        index += 1;
        continue;
      }
      const key = unquoteYamlScalar(line.content.slice(0, colonIndex));
      const valueToken = line.content.slice(colonIndex + 1).trim();
      index += 1;
      if (valueToken) {
        out[key] = parseYamlScalar(valueToken);
        continue;
      }
      if (index < lines.length && lines[index].indent > indentLevel) {
        out[key] = parseNode(lines[index].indent);
      } else {
        out[key] = null;
      }
    }
    return out;
  };

  const parseSequence = (indentLevel: number): unknown[] => {
    const values: unknown[] = [];
    while (index < lines.length) {
      const line = lines[index];
      if (line.indent < indentLevel) break;
      if (line.indent !== indentLevel || !line.content.startsWith("- ")) break;
      const valueToken = line.content.slice(2).trim();
      index += 1;
      if (valueToken) {
        values.push(parseYamlScalar(valueToken));
        if (index < lines.length && lines[index].indent > indentLevel) {
          // Consume malformed continuation lines to keep parser state stable.
          parseNode(lines[index].indent);
        }
        continue;
      }
      if (index < lines.length && lines[index].indent > indentLevel) {
        values.push(parseNode(lines[index].indent));
      } else {
        values.push(null);
      }
    }
    return values;
  };

  const root = parseNode(0);
  return toObjectRecord(root) || {};
}

function parsePnpmWorkspacePackagesFallback(yaml: string): string[] {
  const patterns: string[] = [];
  const lines = yaml.split(/\r?\n/);
  let inPackages = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (/^packages\s*:\s*$/.test(trimmed)) {
      inPackages = true;
      continue;
    }
    if (inPackages) {
      if (/^[A-Za-z0-9_-]+\s*:/.test(trimmed) && !trimmed.startsWith("-")) {
        inPackages = false;
        continue;
      }
      const m = trimmed.match(/^[-]\s*["']?([^"']+)["']?\s*$/);
      if (m && m[1]) patterns.push(m[1].trim());
    }
  }
  return patterns;
}

function parsePnpmWorkspaceFile(yaml: string): {
  packages: string[];
  overrides?: Record<string, unknown>;
} {
  const parsed = parseSimpleYaml(yaml);
  const fromYaml = normalizeStringArray(parsed.packages);
  const fromFallback = fromYaml.length > 0
    ? fromYaml
    : parsePnpmWorkspacePackagesFallback(yaml);
  const topLevelOverrides = toObjectRecord(parsed.overrides);
  const pnpmOverrides = toObjectRecord(
    toObjectRecord(parsed.pnpm)?.overrides,
  );
  const overrides = mergeRecordObjects(topLevelOverrides, pnpmOverrides);
  return {
    packages: fromFallback,
    ...(overrides ? { overrides } : {}),
  };
}

async function getToolVersion(
  tool: string,
  cwd: string,
): Promise<string | undefined> {
  try {
    const result = await runCommand(tool, ["--version"], { cwd });
    const raw = (result.stdout || "").trim();
    if (!raw) return undefined;
    return raw.split(/\s+/)[0];
  } catch {
    return undefined;
  }
}

function compactToolVersions(
  versions: Record<string, string | undefined>,
): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(versions)) {
    if (value) out[key] = value;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

async function detectYarnPnP(projectPath: string): Promise<boolean> {
  if (
    (await pathExists(path.join(projectPath, ".pnp.cjs"))) ||
    (await pathExists(path.join(projectPath, ".pnp.js")))
  ) {
    return true;
  }

  const yarnrc = path.join(projectPath, ".yarnrc.yml");
  if (!(await pathExists(yarnrc))) return false;
  const content = await fs.readFile(yarnrc, "utf8").catch(() => "");
  return /nodeLinker\s*:\s*pnp\b/.test(content);
}

async function detectWorkspace(
  projectPath: string,
): Promise<WorkspaceDiscovery> {
  const rootPkgPath = path.join(projectPath, "package.json");
  const rootPkg = await readJsonFile(rootPkgPath);
  const inferredManager = inferPackageManager(rootPkg);
  const hasYarnLock = await pathExists(path.join(projectPath, "yarn.lock"));
  const hasYarnPnp = await detectYarnPnP(projectPath);

  const pnpmWorkspacePath = path.join(projectPath, "pnpm-workspace.yaml");
  const hasPnpmWorkspace = await pathExists(pnpmWorkspacePath);

  let type: WorkspaceType = "none";
  let patterns: string[] = [];
  let pnpmWorkspaceOverrides: Record<string, unknown> | undefined;

  if (hasPnpmWorkspace) {
    type = "pnpm";
    const yaml = await fs.readFile(pnpmWorkspacePath, "utf8");
    const workspaceFile = parsePnpmWorkspaceFile(yaml);
    patterns = workspaceFile.packages;
    pnpmWorkspaceOverrides = workspaceFile.overrides;
  }

  if (hasYarnPnp) {
    return { type: "yarn", packagePaths: [] };
  }

  // npm/yarn workspaces
  if (type === "none" && rootPkg && rootPkg.workspaces) {
    type = inferredManager || (hasYarnLock ? "yarn" : "npm");
    if (Array.isArray(rootPkg.workspaces)) patterns = rootPkg.workspaces;
    else if (Array.isArray(rootPkg.workspaces.packages))
      patterns = rootPkg.workspaces.packages;
  }

  if (type === "none") {
    return { type: "none", packagePaths: [projectPath] };
  }

  // Expand patterns and keep only folders that contain package.json
  const candidates: string[] = [];
  for (const pat of patterns) {
    const expanded = await expandWorkspacePattern(projectPath, pat);
    candidates.push(...expanded);
  }

  const unique = Array.from(
    new Set(candidates.map((p) => path.resolve(p))),
  ).filter((p) => !normalizeSlashes(p).includes("/node_modules/"));

  const packagePaths: string[] = [];
  for (const dir of unique) {
    const pkgJson = path.join(dir, "package.json");
    if (await pathExists(pkgJson)) packagePaths.push(dir);
  }

  // Always include root if it contains a name (some repos keep a root package)
  if (await pathExists(path.join(projectPath, "package.json"))) {
    // root may already be in the list; keep unique
    if (!packagePaths.includes(projectPath)) {
      // Only include root as a scanned package if it looks like a real package
      const root = await readJsonFile(path.join(projectPath, "package.json"));
      if (
        root &&
        typeof root.name === "string" &&
        root.name.trim().length > 0
      ) {
        packagePaths.push(projectPath);
      }
    }
  }

  return {
    type,
    packagePaths: packagePaths.sort(),
    ...(pnpmWorkspaceOverrides ? { pnpmWorkspaceOverrides } : {}),
  };
}

function inferPackageManager(rootPkg: any): PackageManager | undefined {
  const raw =
    typeof rootPkg?.packageManager === "string"
      ? rootPkg.packageManager.trim()
      : "";
  if (!raw) return undefined;
  if (raw.startsWith("pnpm@") || raw === "pnpm") return "pnpm";
  if (raw.startsWith("yarn@") || raw === "yarn") return "yarn";
  if (raw.startsWith("npm@") || raw === "npm") return "npm";
  return undefined;
}

async function detectPackageManager(
  projectPath: string,
  rootPkg: any,
  workspaceType: WorkspaceType,
): Promise<PackageManager> {
  const inferred = inferPackageManager(rootPkg);
  if (inferred) return inferred;
  if (workspaceType === "pnpm" || workspaceType === "yarn")
    return workspaceType;
  if (await detectYarnPnP(projectPath)) return "yarn";
  if (await pathExists(path.join(projectPath, "node_modules", ".pnpm")))
    return "pnpm";
  if (
    await pathExists(path.join(projectPath, "node_modules", ".yarn-state.yml"))
  )
    return "yarn";
  return "npm";
}

async function detectScanManager(
  projectPath: string,
  fallback: PackageManager,
): Promise<PackageManager> {
  if (await pathExists(path.join(projectPath, "pnpm-lock.yaml"))) return "pnpm";
  if (await pathExists(path.join(projectPath, "yarn.lock"))) return "yarn";
  if (
    (await pathExists(path.join(projectPath, "package-lock.json"))) ||
    (await pathExists(path.join(projectPath, "npm-shrinkwrap.json")))
  ) {
    return "npm";
  }
  if (await pathExists(path.join(projectPath, "node_modules", ".pnpm")))
    return "pnpm";
  if (
    await pathExists(path.join(projectPath, "node_modules", ".yarn-state.yml"))
  )
    return "yarn";
  return fallback;
}

async function readWorkspacePackageMeta(
  rootPath: string,
  packagePaths: string[],
): Promise<WorkspacePackageMeta[]> {
  const out: WorkspacePackageMeta[] = [];
  for (const p of packagePaths) {
    const pkg = await readJsonFile(path.join(p, "package.json"));
    const name =
      pkg && typeof pkg.name === "string" && pkg.name.trim()
        ? pkg.name.trim()
        : path.basename(p);
    out.push({ path: p, name, pkg: pkg || {} });
  }
  return out;
}

function isWorkspaceLocalSpecifier(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const trimmed = value.trim().toLowerCase();
  return (
    trimmed.startsWith("workspace:") ||
    trimmed.startsWith("link:") ||
    trimmed.startsWith("file:")
  );
}

function normalizeRelativePath(rootPath: string, packagePath: string): string {
  const relative = path.relative(rootPath, packagePath);
  const normalized = relative.split(path.sep).join("/");
  return normalized && normalized.length > 0 ? normalized : ".";
}

function readDependencyEntries(source: any): Array<[string, string]> {
  if (!source || typeof source !== "object") return [];
  const entries: Array<[string, string]> = [];
  for (const [name, spec] of Object.entries<any>(source)) {
    if (typeof name !== "string" || !name.trim()) continue;
    if (typeof spec !== "string" || !spec.trim()) continue;
    entries.push([name, spec.trim()]);
  }
  return entries;
}

function isWorkspaceLocalDependency(
  dependencyName: string,
  spec: string,
  workspacePackageNames: Set<string>,
): boolean {
  return workspacePackageNames.has(dependencyName) || isWorkspaceLocalSpecifier(spec);
}

function buildWorkspaceClassification(
  rootPath: string,
  packageMetas: WorkspacePackageMeta[],
): {
  workspacePackages: WorkspacePackage[];
  workspacePackageNames: Set<string>;
  workspacePackageIds: Set<string>;
  workspacePackagePaths: Set<string>;
  localDependencyNames: Set<string>;
} {
  const workspacePackageNames = new Set(packageMetas.map((meta) => meta.name));
  const workspacePackageIds = new Set<string>();
  const workspacePackagePaths = new Set<string>();
  const localDependencyNames = new Set<string>();
  const workspacePackages: WorkspacePackage[] = [];

  for (const meta of packageMetas) {
    const version =
      typeof meta.pkg?.version === "string" && meta.pkg.version.trim().length > 0
        ? meta.pkg.version.trim()
        : "workspace";
    workspacePackageIds.add(`${meta.name}@${version}`);
    workspacePackagePaths.add(path.resolve(meta.path));

    const runtimeExternal = new Set<string>();
    const devExternal = new Set<string>();

    const runtimeEntries = [
      ...readDependencyEntries(meta.pkg?.dependencies),
      ...readDependencyEntries(meta.pkg?.optionalDependencies),
    ];
    const devEntries = readDependencyEntries(meta.pkg?.devDependencies);
    const peerEntries = readDependencyEntries(meta.pkg?.peerDependencies);

    for (const [depName, spec] of runtimeEntries) {
      if (isWorkspaceLocalDependency(depName, spec, workspacePackageNames)) {
        localDependencyNames.add(depName);
        continue;
      }
      runtimeExternal.add(depName);
    }
    for (const [depName, spec] of devEntries) {
      if (isWorkspaceLocalDependency(depName, spec, workspacePackageNames)) {
        localDependencyNames.add(depName);
        continue;
      }
      devExternal.add(depName);
    }
    for (const [depName, spec] of peerEntries) {
      if (isWorkspaceLocalDependency(depName, spec, workspacePackageNames)) {
        localDependencyNames.add(depName);
      }
    }

    workspacePackages.push({
      name: meta.name,
      relativePath: normalizeRelativePath(rootPath, meta.path),
      directExternal: {
        runtime: runtimeExternal.size,
        dev: devExternal.size,
      },
    });
  }

  workspacePackages.sort((a, b) => {
    const pathCompare = a.relativePath.localeCompare(b.relativePath);
    if (pathCompare !== 0) return pathCompare;
    return a.name.localeCompare(b.name);
  });

  return {
    workspacePackages,
    workspacePackageNames,
    workspacePackageIds,
    workspacePackagePaths,
    localDependencyNames,
  };
}

function mergeDepsFromWorkspace(
  pkgs: WorkspacePackageMeta[],
  workspacePackageNames: Set<string>,
  localDependencyNames: Set<string>,
): any {
  const merged: any = {
    dependencies: {},
    devDependencies: {},
    optionalDependencies: {},
    peerDependencies: {},
  };

  const mergeSection = (target: Record<string, string>, source: any) => {
    for (const [depName, spec] of readDependencyEntries(source)) {
      if (isWorkspaceLocalDependency(depName, spec, workspacePackageNames)) {
        localDependencyNames.add(depName);
        continue;
      }
      target[depName] = spec;
    }
  };

  for (const entry of pkgs) {
    mergeSection(merged.dependencies, entry.pkg?.dependencies);
    mergeSection(merged.devDependencies, entry.pkg?.devDependencies);
    mergeSection(merged.optionalDependencies, entry.pkg?.optionalDependencies);
    mergeSection(merged.peerDependencies, entry.pkg?.peerDependencies);
  }
  return merged;
}

function mergeAuditResults(results: Array<any | undefined>): any | undefined {
  const defined = results.filter(Boolean);
  if (defined.length === 0) return undefined;
  const base: any = {};
  for (const r of defined) {
    if (!r || typeof r !== "object") continue;
    // npm audit v7+ shape: { vulnerabilities: {..} }
    if (r.vulnerabilities && typeof r.vulnerabilities === "object") {
      base.vulnerabilities = base.vulnerabilities || {};
      for (const [k, v] of Object.entries<any>(r.vulnerabilities)) {
        if (!base.vulnerabilities[k]) base.vulnerabilities[k] = v;
        else {
          // merge counts best-effort
          const existing = base.vulnerabilities[k];
          base.vulnerabilities[k] = { ...existing, ...v };
        }
      }
    }
    // legacy shape
    if (r.advisories && typeof r.advisories === "object") {
      base.advisories = base.advisories || {};
      Object.assign(base.advisories, r.advisories);
    }
    // keep metadata if present
    if (r.metadata && !base.metadata) base.metadata = r.metadata;
  }
  return base;
}

function parseOutdatedData(
  data: any,
  unknownNames: Set<string>,
): OutdatedEntry[] {
  const entries: OutdatedEntry[] = [];
  if (!data || typeof data !== "object") return entries;
  if (Array.isArray(data)) {
    for (const entry of data) {
      if (!entry || typeof entry !== "object") continue;
      const name = typeof entry.name === "string" ? entry.name : undefined;
      const current = typeof entry.current === "string" ? entry.current : "";
      const latest =
        typeof entry.latest === "string" ? entry.latest : undefined;
      const type =
        typeof entry.type === "string" ? entry.type.toLowerCase() : "";
      if (!name || !current) continue;
      let status: "patch" | "minor" | "major" | "unknown" | "current" =
        "unknown";
      if (type === "patch" || type === "minor" || type === "major") {
        status = type;
      } else if (latest) {
        status = classifyOutdated(current, latest);
      }
      if (status === "current") continue;
      if (status === "major" || status === "minor" || status === "patch") {
        entries.push({
          name,
          currentVersion: current,
          status,
          latestVersion: latest,
        });
        continue;
      }
      entries.push({ name, currentVersion: current, status: "unknown" });
    }
    return entries;
  }
  for (const [name, info] of Object.entries<any>(data)) {
    if (!info || typeof info !== "object") {
      unknownNames.add(name);
      continue;
    }
    const current = typeof info.current === "string" ? info.current : "";
    const latest = typeof info.latest === "string" ? info.latest : undefined;
    const type = typeof info.type === "string" ? info.type.toLowerCase() : "";
    if (!current) {
      unknownNames.add(name);
      continue;
    }
    let status: "patch" | "minor" | "major" | "unknown" | "current" = "unknown";
    if (type === "patch" || type === "minor" || type === "major") {
      status = type;
    } else if (latest) {
      status = classifyOutdated(current, latest);
    }

    if (status === "current") continue;
    if (status === "major" || status === "minor" || status === "patch") {
      if (latest) {
        entries.push({
          name,
          currentVersion: current,
          status,
          latestVersion: latest,
        });
      } else {
        entries.push({ name, currentVersion: current, status: "unknown" });
      }
      continue;
    }
    entries.push({ name, currentVersion: current, status: "unknown" });
  }
  return entries;
}

function parseSimpleVersion(
  value: string,
): { major: number; minor: number; patch: number } | undefined {
  if (!value || typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  if (trimmed.includes("-") || trimmed.includes("+")) return undefined;
  const match = trimmed.match(/^v?(\d+)\.(\d+)\.(\d+)$/);
  if (!match) return undefined;
  const major = Number.parseInt(match[1], 10);
  const minor = Number.parseInt(match[2], 10);
  const patch = Number.parseInt(match[3], 10);
  if ([major, minor, patch].some((n) => Number.isNaN(n))) return undefined;
  return { major, minor, patch };
}

function classifyOutdated(
  current: string,
  latest: string,
): "major" | "minor" | "patch" | "current" | "unknown" {
  const currentVer = parseSimpleVersion(current);
  const latestVer = parseSimpleVersion(latest);
  if (!currentVer || !latestVer) return "unknown";
  if (currentVer.major !== latestVer.major) return "major";
  if (currentVer.minor !== latestVer.minor) return "minor";
  if (currentVer.patch !== latestVer.patch) return "patch";
  return "current";
}

function mergeOutdatedResults(
  results: OutdatedAttempt[],
): OutdatedResult | undefined {
  const entries: OutdatedEntry[] = [];
  const unknownNames = new Set<string>();

  for (let i = 0; i < results.length; i++) {
    const attempt = results[i];
    if (!attempt.attempted) continue;
    const result = attempt.result;
    if (
      !result ||
      !result.ok ||
      !result.data ||
      typeof result.data !== "object"
    ) {
      continue;
    }
    entries.push(...parseOutdatedData(result.data, unknownNames));
  }

  if (entries.length === 0 && unknownNames.size === 0) {
    return undefined;
  }

  const merged = new Map<string, OutdatedEntry>();
  for (const entry of entries) {
    const key = `${entry.name}@${entry.currentVersion}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, entry);
      continue;
    }
    if (
      existing.status !== entry.status ||
      existing.latestVersion !== entry.latestVersion
    ) {
      merged.set(key, {
        name: entry.name,
        currentVersion: entry.currentVersion,
        status: "unknown",
      });
    }
  }

  return {
    entries: Array.from(merged.values()),
    unknownNames: Array.from(unknownNames),
  };
}

function mergeImportGraphs(
  rootPath: string,
  packageMetas: Array<{ path: string; name: string }>,
  graphs: Array<any | undefined>,
): any {
  const files: Record<string, string[]> = {};
  const packages: Record<string, string[]> = {};
  const packageCounts: Record<string, Record<string, number>> = {};
  const unresolvedImports: Array<{ importer: string; specifier: string }> = [];

  for (let i = 0; i < graphs.length; i++) {
    const g = graphs[i];
    const meta = packageMetas[i];
    if (!g || typeof g !== "object") continue;
    const relBase = path
      .relative(rootPath, meta.path)
      .split(path.sep)
      .join("/");
    const prefix = relBase ? `${relBase}/` : "";

    const gf = g.files || {};
    const gp = g.packages || {};
    const gc = g.packageCounts || {};
    for (const [k, v] of Object.entries<any>(gf)) {
      files[`${prefix}${k}`] = Array.isArray(v)
        ? v.map((x) => `${prefix}${x}`)
        : [];
    }
    for (const [k, v] of Object.entries<any>(gp)) {
      packages[`${prefix}${k}`] = Array.isArray(v) ? v : [];
    }
    for (const [k, v] of Object.entries<any>(gc)) {
      if (!v || typeof v !== "object") continue;
      const next: Record<string, number> = {};
      for (const [dep, count] of Object.entries<any>(v)) {
        if (typeof count === "number") next[dep] = count;
      }
      packageCounts[`${prefix}${k}`] = next;
    }
    const unresolved = Array.isArray(g.unresolvedImports)
      ? g.unresolvedImports
      : [];
    unresolved.forEach((u: any) => {
      if (
        u &&
        typeof u.importer === "string" &&
        typeof u.specifier === "string"
      ) {
        unresolvedImports.push({
          importer: `${prefix}${u.importer}`,
          specifier: u.specifier,
        });
      }
    });
  }

  return { files, packages, packageCounts, unresolvedImports };
}

function buildWorkspaceUsageMap(
  packageMetas: WorkspacePackageMeta[],
  dependencyGraphs: Array<any | undefined>,
  workspacePackageNames: Set<string>,
  localDependencyNames: Set<string>,
): Map<string, string[]> {
  const usage = new Map<string, Set<string>>();

  const add = (depName: string, pkgName: string) => {
    if (!depName) return;
    if (workspacePackageNames.has(depName)) return;
    if (localDependencyNames.has(depName)) return;
    if (!usage.has(depName)) usage.set(depName, new Set());
    usage.get(depName)!.add(pkgName);
  };

  // From declared deps
  for (const meta of packageMetas) {
    const pkgName = meta.name;
    const deps = meta.pkg?.dependencies || {};
    const dev = meta.pkg?.devDependencies || {};
    const opt = meta.pkg?.optionalDependencies || {};
    const peer = meta.pkg?.peerDependencies || {};
    Object.keys(deps).forEach((d) => {
      add(d, pkgName);
    });
    Object.keys(dev).forEach((d) => {
      add(d, pkgName);
    });
    Object.keys(opt).forEach((d) => {
      add(d, pkgName);
    });
    Object.keys(peer).forEach((d) => {
      add(d, pkgName);
    });
  }

  // From npm ls trees (transitives)
  const walk = (node: any, pkgName: string): void => {
    if (!node || typeof node !== "object") return;
    const name = node.name;
    if (typeof name === "string") add(name, pkgName);
    const deps = node.dependencies;
    if (deps && typeof deps === "object") {
      for (const [depName, child] of Object.entries<any>(deps)) {
        add(depName, pkgName);
        walk(child, pkgName);
      }
    }
  };

  for (let i = 0; i < dependencyGraphs.length; i++) {
    const data = dependencyGraphs[i];
    const meta = packageMetas[i];
    if (!data || typeof data !== "object") continue;
    const deps = data.dependencies;
    if (deps && typeof deps === "object") {
      for (const [depName, child] of Object.entries<any>(deps)) {
        add(depName, meta.name);
        walk(child, meta.name);
      }
    }
  }

  const out = new Map<string, string[]>();
  for (const [k, set] of usage.entries()) {
    out.set(k, Array.from(set).sort());
  }
  return out;
}

function buildCombinedDependencyGraph(
  rootPath: string,
  packageMetas: WorkspacePackageMeta[],
  dependencyGraphs: Array<any | undefined>,
): any {
  // Build a synthetic root with each workspace package as a top-level node.
  // This avoids object-key collisions for normal packages and preserves per-package roots.
  const dependencies: Record<string, any> = {};

  for (let i = 0; i < dependencyGraphs.length; i++) {
    const data = dependencyGraphs[i];
    const meta = packageMetas[i];
    if (!meta) continue;
    const version =
      typeof meta.pkg?.version === "string" ? meta.pkg.version : "workspace";
    const nodeDeps =
      data &&
      typeof data === "object" &&
      data.dependencies &&
      typeof data.dependencies === "object"
        ? data.dependencies
        : {};

    dependencies[meta.name] = {
      name: meta.name,
      version,
      dependencies: nodeDeps,
    };
  }

  return { name: "dependency-radar-workspace", version: "0.0.0", dependencies };
}

interface CliOptions {
  command: "scan";
  project: string;
  out: string;
  keepTemp: boolean;
  audit: boolean;
  outdated: boolean;
  json: boolean;
  open: boolean;
  noReport: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    command: "scan",
    project: process.cwd(),
    out: "dependency-radar.html",
    keepTemp: false,
    audit: true,
    outdated: true,
    json: false,
    open: false,
    noReport: false,
  };

  const args = [...argv];
  if (args[0] && !args[0].startsWith("-")) {
    opts.command = args.shift() as "scan";
  }

  while (args.length) {
    const arg = args.shift();
    if (!arg) break;
    if (arg === "--project" && args[0]) opts.project = args.shift()!;
    else if (arg === "--out" && args[0]) opts.out = args.shift()!;
    else if (arg === "--keep-temp") opts.keepTemp = true;
    else if (arg === "--offline") {
      opts.audit = false;
      opts.outdated = false;
    } else if (arg === "--json") opts.json = true;
    else if (arg === "--open") opts.open = true;
    else if (arg === "--no-report") opts.noReport = true;
    else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
  }

  return opts;
}

function printHelp(): void {
  console.log(`dependency-radar [scan] [options]

If no command is provided, \`scan\` is run by default.

Options:
  --project <path>   Project folder (default: cwd)
  --out <path>       Output HTML file (default: dependency-radar.html)
  --json             Write aggregated data to JSON (default filename: dependency-radar.json)
  --no-report        Do not write HTML/JSON report files or temp artifacts to disk
  --keep-temp        Keep .dependency-radar folder
  --offline          Skip npm audit and npm outdated (useful for offline scans)
  --open             Open the generated report using the system default application
`);
}

function openInBrowser(filePath: string): void {
  const normalizedPath = filePath.replace(/\\/g, "/");
  let child: ChildProcess;

  switch (platform()) {
    case "darwin":
      child = spawn("open", [normalizedPath], {
        stdio: "ignore",
        shell: false,
        detached: true,
      });
      break;
    case "win32":
      child = spawn("cmd", ["/c", "start", "", normalizedPath], {
        stdio: "ignore",
        shell: false,
        detached: true,
      });
      break;
    default:
      child = spawn("xdg-open", [normalizedPath], {
        stdio: "ignore",
        shell: false,
        detached: true,
      });
      break;
  }

  child.on("error", (err) => {
    console.warn("Could not open report:", err.message);
  });
  child.unref();
}

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
} as const;

function shouldUseColor(): boolean {
  if (process.env.NO_COLOR !== undefined) return false;
  const forceColor = process.env.FORCE_COLOR;
  if (forceColor === "0") return false;
  if (forceColor !== undefined) return true;
  return Boolean(process.stdout.isTTY);
}

const COLOR_ENABLED = shouldUseColor();

function styleText(
  value: string,
  color: "bold" | "green" | "red" | "yellow" | "cyan",
): string {
  if (!COLOR_ENABLED) return value;
  return `${ANSI[color]}${value}${ANSI.reset}`;
}

function splitFirstGlyph(value: string): { head: string; tail: string } {
  const chars = Array.from(value);
  const head = chars[0] || "";
  const tail = value.slice(head.length);
  return { head, tail };
}

function colorSymbol(symbol: string): string {
  const { head, tail } = splitFirstGlyph(symbol);
  if (!head) return symbol;
  if (head === "✔") return `${styleText(head, "green")}${tail}`;
  if (head === "✖") return `${styleText(head, "red")}${tail}`;
  if (head === "⚠") return `${styleText(head, "yellow")}${tail}`;
  if (head === "↗" || head === "ℹ" || head === "📦") {
    return `${styleText(head, "cyan")}${tail}`;
  }
  if (head === "📉") return `${styleText(head, "yellow")}${tail}`;
  return symbol;
}

function colorLeadingSymbol(line: string): string {
  const { head } = splitFirstGlyph(line);
  if (!head) return line;
  if (
    head !== "✔" &&
    head !== "✖" &&
    head !== "⚠" &&
    head !== "↗" &&
    head !== "ℹ" &&
    head !== "📦" &&
    head !== "📉"
  ) {
    return line;
  }
  return `${colorSymbol(head)}${line.slice(head.length)}`;
}

function statusLine(symbol: string, message: string): string {
  return `${colorSymbol(symbol)} ${message}`;
}

type CliSummary = {
  directDeps: number;
  transitiveDeps: number;
  vulnerablePackages: number;
  reachableVulnerablePackages: number;
  unusedInstalledDeps: number;
  licenseMismatches: number;
  majorUpgradeBlockers: number;
  majorUpgradeBlockerBreakdown: {
    peerDependency: number;
    nodeEngine: number;
    deprecated: number;
    nativeBindings: number;
    installScripts: number;
  };
};

function buildCliSummary(
  aggregated: AggregatedData,
  options: { importGraphComplete: boolean },
): CliSummary {
  let vulnerablePackages = 0;
  let reachableVulnerablePackages = 0;
  let unusedInstalledDeps = 0;
  let licenseMismatches = 0;
  let majorUpgradeBlockers = 0;
  const majorUpgradeBlockerBreakdown = {
    peerDependency: 0,
    nodeEngine: 0,
    deprecated: 0,
    nativeBindings: 0,
    installScripts: 0,
  };

  const deps = Object.values(aggregated.dependencies || {});
  for (const dep of deps) {
    const vulnTotal =
      (dep.security.summary.critical || 0) +
      (dep.security.summary.high || 0) +
      (dep.security.summary.moderate || 0) +
      (dep.security.summary.low || 0);
    if (vulnTotal > 0) {
      vulnerablePackages += 1;
      if ((dep.usage.importUsage?.fileCount || 0) > 0) {
        reachableVulnerablePackages += 1;
      }
    }
    // Count "unused" only when import graph collection succeeded for all packages.
    // Otherwise, missing importUsage can mean "unknown" rather than "unused".
    if (
      options.importGraphComplete &&
      dep.usage.direct &&
      dep.usage.scope === "runtime" &&
      !dep.usage.importUsage
    ) {
      unusedInstalledDeps += 1;
    }
    if (dep.compliance.license.status === "mismatch") {
      licenseMismatches += 1;
    }
    const blockers = dep.upgrade.blockers || [];
    if (blockers.length > 0) {
      majorUpgradeBlockers += 1;
    }
    if (blockers.includes("peerDependency")) {
      majorUpgradeBlockerBreakdown.peerDependency += 1;
    }
    if (blockers.includes("nodeEngine")) {
      majorUpgradeBlockerBreakdown.nodeEngine += 1;
    }
    if (blockers.includes("deprecated")) {
      majorUpgradeBlockerBreakdown.deprecated += 1;
    }
    if (blockers.includes("nativeBindings")) {
      majorUpgradeBlockerBreakdown.nativeBindings += 1;
    }
    if (blockers.includes("installScripts")) {
      majorUpgradeBlockerBreakdown.installScripts += 1;
    }
  }

  return {
    directDeps: aggregated.summary.directCount,
    transitiveDeps: aggregated.summary.transitiveCount,
    vulnerablePackages,
    reachableVulnerablePackages,
    unusedInstalledDeps,
    licenseMismatches,
    majorUpgradeBlockers,
    majorUpgradeBlockerBreakdown,
  };
}

function pluralize(value: number, singular: string, plural: string): string {
  return value === 1 ? singular : plural;
}

function printCliSummary(summary: CliSummary): void {
  const bullet = "•";
  console.log("");
  console.log("Summary:");
  console.log(`${bullet} Direct deps scanned: ${summary.directDeps}`);
  console.log(`${bullet} Transitive deps scanned: ${summary.transitiveDeps}`);
  console.log(
    `${bullet} Vulnerable packages: ${summary.vulnerablePackages} (${summary.reachableVulnerablePackages} reachable)`,
  );
  console.log(`${bullet} Unused installed deps: ${summary.unusedInstalledDeps}`);
  console.log(`${bullet} Licence mismatches: ${summary.licenseMismatches}`);
  console.log(`${bullet} Major upgrade blockers: ${summary.majorUpgradeBlockers}`);
  const blockerDetails: string[] = [];
  if (summary.majorUpgradeBlockerBreakdown.peerDependency > 0) {
    blockerDetails.push(
      `   - ${summary.majorUpgradeBlockerBreakdown.peerDependency} ${pluralize(
        summary.majorUpgradeBlockerBreakdown.peerDependency,
        "strict peer dependency constraint",
        "strict peer dependency constraints",
      )}`,
    );
  }
  if (summary.majorUpgradeBlockerBreakdown.nodeEngine > 0) {
    blockerDetails.push(
      `   - ${summary.majorUpgradeBlockerBreakdown.nodeEngine} ${pluralize(
        summary.majorUpgradeBlockerBreakdown.nodeEngine,
        "narrow engine range",
        "narrow engine ranges",
      )}`,
    );
  }
  if (summary.majorUpgradeBlockerBreakdown.deprecated > 0) {
    blockerDetails.push(
      `   - ${summary.majorUpgradeBlockerBreakdown.deprecated} ${pluralize(
        summary.majorUpgradeBlockerBreakdown.deprecated,
        "deprecated package",
        "deprecated packages",
      )}`,
    );
  }
  if (summary.majorUpgradeBlockerBreakdown.nativeBindings > 0) {
    blockerDetails.push(
      `   - ${summary.majorUpgradeBlockerBreakdown.nativeBindings} ${pluralize(
        summary.majorUpgradeBlockerBreakdown.nativeBindings,
        "native binding",
        "native bindings",
      )}`,
    );
  }
  if (summary.majorUpgradeBlockerBreakdown.installScripts > 0) {
    blockerDetails.push(
      `   - ${summary.majorUpgradeBlockerBreakdown.installScripts} ${pluralize(
        summary.majorUpgradeBlockerBreakdown.installScripts,
        "install lifecycle script",
        "install lifecycle scripts",
      )}`,
    );
  }
  for (const line of blockerDetails) {
    console.log(line);
  }
  console.log("");
}

/**
 * Orchestrates the CLI "scan" command to collect, merge, and output dependency data for a project or workspace.
 *
 * Detects workspace type and package manager, runs per-package collectors (audit, dependency tree, import graph, outdated),
 * merges collected signals into a workspace-level model, and writes a JSON or HTML report to the configured output path.
 * Manages a temporary working directory (created under the project as .dependency-radar), respects CLI options such as
 * JSON output, audit/outdated toggles, keeping the temp directory, and optionally opening the generated output with the
 * system default application. Exits the process with a non-zero code on fatal errors. */
async function run(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.command !== "scan") {
    printHelp();
    process.exit(1);
    return;
  }

  const shouldWriteArtifacts = !opts.noReport;
  const projectPath = path.resolve(opts.project);
  let summary: CliSummary | undefined;
  if (opts.noReport && opts.keepTemp) {
    console.log(
      statusLine("⚠", "--keep-temp is ignored when --no-report is enabled."),
    );
  }
  if (opts.json && opts.out === "dependency-radar.html") {
    opts.out = "dependency-radar.json";
  }
  let outputPath = path.resolve(opts.out);
  const startTime = Date.now();
  let dependencyCount = 0;
  let outputCreated = false;
  if (shouldWriteArtifacts) {
    try {
      const stat = await fs.stat(outputPath).catch(() => undefined);
      const endsWithSeparator = opts.out.endsWith("/") || opts.out.endsWith("\\");
      const hasExtension = Boolean(path.extname(outputPath));
      if (
        (stat && stat.isDirectory()) ||
        endsWithSeparator ||
        (!stat && !hasExtension)
      ) {
        outputPath = path.join(
          outputPath,
          opts.json ? "dependency-radar.json" : "dependency-radar.html",
        );
      }
    } catch (e) {
      // ignore, best-effort path normalization
    }
  }
  const tempDir = path.join(projectPath, ".dependency-radar");

  // Stage 1: detect workspace/package-manager context and collect tool versions.
  const workspace = await detectWorkspace(projectPath);
  const yarnPnP = await detectYarnPnP(projectPath);
  if (workspace.type === "yarn" && workspace.packagePaths.length === 0) {
    console.error(
      "Yarn Plug'n'Play (nodeLinker: pnp) detected. This is not supported yet.",
    );
    console.error(
      "Switch to nodeLinker: node-modules or run in a non-PnP environment.",
    );
    process.exit(1);
    return;
  }
  const hasProjectNodeModules = await pathExists(
    path.join(projectPath, "node_modules"),
  );
  if (!hasProjectNodeModules) {
    const workspaceHint =
      workspace.type === "none"
        ? "single project"
        : `${workspace.type.toUpperCase()} workspace`;
    const yarnHint = yarnPnP
      ? " Yarn Plug'n'Play appears enabled; Dependency Radar currently requires node_modules linker."
      : "";
    console.warn(
      colorLeadingSymbol(
        `⚠ node_modules was not found at ${projectPath}. Scan completeness may be reduced for this ${workspaceHint}. Run your package manager install (npm install, pnpm install, or yarn install) before scanning.${yarnHint}`,
      ),
    );
  }
  const rootPkg = await readJsonFile(path.join(projectPath, "package.json"));
  const projectDependencyPolicy = workspace.pnpmWorkspaceOverrides
    ? {
        overrides: workspace.pnpmWorkspaceOverrides,
        sources: ["pnpm-workspace.yaml#overrides"],
      }
    : undefined;
  const packageManager = await detectPackageManager(
    projectPath,
    rootPkg,
    workspace.type,
  );
  const scanManager = await detectScanManager(projectPath, packageManager);
  const packageManagerField =
    typeof rootPkg?.packageManager === "string"
      ? rootPkg.packageManager.trim()
      : undefined;
  const [npmVersion, pnpmVersion, yarnVersion] = await Promise.all([
    getToolVersion("npm", projectPath),
    getToolVersion("pnpm", projectPath),
    getToolVersion("yarn", projectPath),
  ]);
  const toolVersions = compactToolVersions({
    npm: npmVersion,
    pnpm: pnpmVersion,
    yarn: yarnVersion,
  });
  const packageManagerVersion =
    scanManager === "npm"
      ? npmVersion
      : scanManager === "pnpm"
        ? pnpmVersion
        : yarnVersion;
  if (packageManager === "yarn" && yarnPnP) {
    console.error(
      "Yarn Plug'n'Play (nodeLinker: pnp) detected. This is not supported yet.",
    );
    console.error(
      "Switch to nodeLinker: node-modules or run in a non-PnP environment.",
    );
    process.exit(1);
    return;
  }

  const packagePaths = workspace.packagePaths;
  const workspaceLabel =
    workspace.type === "none"
      ? "Single project"
      : `${workspace.type.toUpperCase()} workspace`;
  console.log(statusLine("✔", `${workspaceLabel} detected`));
  if (workspace.type !== "none" && scanManager !== workspace.type) {
    console.log(
      statusLine(
        "✔",
        `Using ${scanManager.toUpperCase()} for dependency data (lockfile detected)`,
      ),
    );
  }
  const spinner = startSpinner(`Scanning ${workspaceLabel} at ${projectPath}`);
  try {
    if (shouldWriteArtifacts) {
      await ensureDir(tempDir);
    }

    // Stage 2: run per-package collectors and persist raw tool outputs.
    const packageMetas = await readWorkspacePackageMeta(
      projectPath,
      packagePaths,
    );
    const workspaceClassification = buildWorkspaceClassification(
      projectPath,
      packageMetas,
    );

    const perPackageAudit: Array<ToolResult<any> | undefined> = [];
    const perPackageLs: Array<ToolResult<any>> = [];
    const perPackageImportGraph: Array<ToolResult<any>> = [];
    const perPackageOutdated: OutdatedAttempt[] = [];

    for (const meta of packageMetas) {
      spinner.update(
        `Scanning ${workspaceLabel} (${perPackageLs.length + 1}/${packageMetas.length}) at ${projectPath}`,
      );
      const pkgTempDir = path.join(
        tempDir,
        meta.name.replace(/[^a-zA-Z0-9._-]/g, "_"),
      );
      if (shouldWriteArtifacts) {
        await ensureDir(pkgTempDir);
      }
      const [a, l, ig, o] = await Promise.all([
        opts.audit
          ? runPackageAudit(
              meta.path,
              pkgTempDir,
              scanManager,
              yarnVersion,
              shouldWriteArtifacts,
            ).catch(
              (err) => ({ ok: false, error: String(err) }) as ToolResult<any>,
            )
          : Promise.resolve(undefined),
        runNpmLs(meta.path, pkgTempDir, scanManager, {
          contextLabel: meta.name,
          lockfileSearchRoot: projectPath,
          onProgress: (line) => spinner.log(line),
          persistToDisk: shouldWriteArtifacts,
        }).catch(
          (err) => ({ ok: false, error: String(err) }) as ToolResult<any>,
        ),
        runImportGraph(meta.path, pkgTempDir, {
          persistToDisk: shouldWriteArtifacts,
        }).catch(
          (err) => ({ ok: false, error: String(err) }) as ToolResult<any>,
        ),
        opts.outdated
          ? runPackageOutdated(
              meta.path,
              pkgTempDir,
              scanManager,
              { persistToDisk: shouldWriteArtifacts },
            ).catch(
              (err) => ({ ok: false, error: String(err) }) as ToolResult<any>,
            )
          : Promise.resolve(undefined),
      ]);
      perPackageAudit.push(a);
      perPackageLs.push(l);
      perPackageImportGraph.push(ig);
      perPackageOutdated.push({ attempted: Boolean(opts.outdated), result: o });
    }

    // Stage 3: merge per-package results into a workspace-level view.
    if (opts.audit) {
      const auditOk = perPackageAudit.every((r) => r && r.ok);
      if (auditOk) {
        spinner.log(
          statusLine("✔", `${scanManager.toUpperCase()} audit data collected`),
        );
      } else {
        spinner.log(
          statusLine("✖", `${scanManager.toUpperCase()} audit data unavailable`),
        );
      }
    }
    if (opts.outdated) {
      const outdatedOk = perPackageOutdated.every(
        (r) => r.result && r.result.ok,
      );
      if (outdatedOk) {
        spinner.log(
          statusLine(
            "✔",
            `${scanManager.toUpperCase()} outdated data collected`,
          ),
        );
      } else {
        spinner.log(
          statusLine(
            "✖",
            `${scanManager.toUpperCase()} outdated data unavailable`,
          ),
        );
      }
    }

    const mergedAuditData = mergeAuditResults(
      perPackageAudit.map((r) => (r && r.ok ? r.data : undefined)),
    );
    const mergedGraphData =
      workspace.type === "none"
        ? perPackageLs[0] && perPackageLs[0].ok
          ? perPackageLs[0].data
          : undefined
        : buildCombinedDependencyGraph(
            projectPath,
            packageMetas,
            perPackageLs.map((r) => (r && r.ok ? r.data : undefined)),
          );
    const mergedImportGraphData = mergeImportGraphs(
      projectPath,
      packageMetas,
      perPackageImportGraph.map((r) => (r && r.ok ? r.data : undefined)),
    );
    const workspaceUsage = buildWorkspaceUsageMap(
      packageMetas,
      perPackageLs.map((r) => (r && r.ok ? r.data : undefined)),
      workspaceClassification.workspacePackageNames,
      workspaceClassification.localDependencyNames,
    );
    const outdatedResult = mergeOutdatedResults(perPackageOutdated);

    const auditResult = mergedAuditData
      ? { ok: true, data: mergedAuditData }
      : undefined;
    const npmLsResult = { ok: true, data: mergedGraphData };
    const importGraphResult = { ok: true, data: mergedImportGraphData };

    // Build a merged package.json view for aggregator direct-dep checks.
    const mergedPkgForAggregator = mergeDepsFromWorkspace(
      packageMetas,
      workspaceClassification.workspacePackageNames,
      workspaceClassification.localDependencyNames,
    );

    const auditFailure = opts.audit
      ? perPackageAudit.find((r) => r && !r.ok)
      : undefined;
    const lsFailures = perPackageLs
      .map((result, index) => ({ result, meta: packageMetas[index] }))
      .filter((entry) => entry.result && !entry.result.ok);
    const importFailures = perPackageImportGraph.filter((r) => r && !r.ok);
    if (auditFailure) {
      spinner.log(`Audit warning: ${auditFailure.error || "Audit failed"}`);
    }
    if (lsFailures.length > 0) {
      const packageList = lsFailures.map((entry) => entry.meta?.name).filter(Boolean);
      spinner.log(
        `Dependency tree warning: ${lsFailures.length} package${lsFailures.length === 1 ? "" : "s"} failed (${packageList.join(", ")}).`,
      );
      spinner.log(
        `First dependency tree error: ${lsFailures[0].result?.error || "pnpm ls failed"}`,
      );
    }
    if (importFailures.length > 0) {
      spinner.log(
        `Import graph warning: ${importFailures.length} package${importFailures.length === 1 ? "" : "s"} failed (${importFailures[0].error || "import graph failed"})`,
      );
    }

    // Stage 4: aggregate all signals into the final report model.
    const aggregated = await aggregateData({
      projectPath,
      auditResult,
      npmLsResult,
      importGraphResult,
      outdatedResult,
      pkgOverride: mergedPkgForAggregator,
      projectPackageJson: rootPkg,
      ...(projectDependencyPolicy ? { projectDependencyPolicy } : {}),
      workspaceUsage,
      resolvePaths: [
        projectPath,
        ...packagePaths.filter((p) => p !== projectPath),
      ],
      workspaceEnabled: workspace.type !== "none",
      workspaceType: workspace.type,
      workspacePackageCount: packagePaths.length,
      ...(workspace.type !== "none"
        ? {
            workspacePackages: workspaceClassification.workspacePackages,
            workspacePackageNames: workspaceClassification.workspacePackageNames,
            workspacePackageIds: workspaceClassification.workspacePackageIds,
            workspacePackagePaths: workspaceClassification.workspacePackagePaths,
            workspaceLocalDependencyNames:
              workspaceClassification.localDependencyNames,
          }
        : {}),
      packageManager: scanManager,
      packageManagerVersion,
      packageManagerField,
      platform: process.platform,
      arch: process.arch,
      ci: isCI(),
      ...(toolVersions ? { toolVersions } : {}),
    });
    dependencyCount = Object.keys(aggregated.dependencies).length;
    const importGraphComplete = perPackageImportGraph.every((result) => result.ok);
    summary = buildCliSummary(aggregated, {
      importGraphComplete,
    });

    if (workspace.type !== "none") {
      console.log(
        `Detected ${workspace.type.toUpperCase()} workspace with ${packagePaths.length} package${packagePaths.length === 1 ? "" : "s"}.`,
      );
    }

    if (dependencyCount > 0 && shouldWriteArtifacts) {
      if (opts.json) {
        await fs.mkdir(path.dirname(outputPath), { recursive: true });
        await fs.writeFile(
          outputPath,
          JSON.stringify(aggregated, null, 2),
          "utf8",
        );
      } else {
        await renderReport(aggregated, outputPath);
      }
      outputCreated = true;
    }
    spinner.stop(true);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(
      statusLine(
        "✔",
        `Scan complete: ${dependencyCount} dependencies analysed in ${elapsed}s`,
      ),
    );
    if (!shouldWriteArtifacts) {
      console.log(
        statusLine("ℹ", "Report output disabled (--no-report); no report artifacts written."),
      );
    } else if (outputCreated) {
      console.log(
        statusLine("✔", `${opts.json ? "JSON" : "Report"} written to ${outputPath}`),
      );
    } else {
      console.log(
        statusLine(
          "✖",
          `No dependencies were found - ${opts.json ? "JSON file" : "Report"} not created`,
        ),
      );
    }
  } catch (err: any) {
    spinner.stop(false);
    console.error("Failed to generate report:", err);
    process.exit(1);
  } finally {
    if (shouldWriteArtifacts) {
      if (!opts.keepTemp) {
        await removeDir(tempDir);
      } else {
        console.log(statusLine("✔", `Temporary data kept at ${tempDir}`));
      }
    }
  }

  if (opts.open && !shouldWriteArtifacts) {
    console.log(statusLine("✖", "Skipping auto-open because --no-report is enabled."));
  } else if (opts.open && outputCreated && !isCI()) {
    console.log(
      statusLine(
        "↗",
        `Opening ${path.basename(outputPath)} using system default ${opts.json ? "application" : "browser"}.`,
      ),
    );
    openInBrowser(outputPath);
  } else if (opts.open && outputCreated && isCI()) {
    console.log(statusLine("✖", "Skipping auto-open in CI environment."));
  }

  if (summary) {
    printCliSummary(summary);
  } else {
    console.log("");
  }

  // Always show CTA as the last output
  console.log(
    "Enrich this scan with maintenance signals, upgrade readiness, and risk modelling at dependency-radar.com",
  );
}

run();

function startSpinner(text: string): {
  stop: (success?: boolean) => void;
  update: (nextText: string) => void;
  log: (line: string) => void;
} {
  const frames = ["|", "/", "-", "\\"];
  let i = 0;
  let currentText = text;
  const shortenPathInMessage = (message: string): string => {
    const marker = ' at ';
    const idx = message.lastIndexOf(marker);
    if (idx === -1) return message;
    const head = message.slice(0, idx + marker.length);
    const rawPath = message.slice(idx + marker.length).trim();
    if (!rawPath) return message;
    const segments = rawPath.split(/[\\/]+/).filter(Boolean);
    if (segments.length === 0) return message;
    const tail = segments.slice(-2).join('/');
    return `${head}…/${tail}`;
  };

  const formatLine = (prefix: string, value: string): string => {
    const coloredPrefix = colorSymbol(prefix);
    if (!process.stdout.isTTY) return `${coloredPrefix} ${value}`;
    const displayValue = shortenPathInMessage(value);
    const columns = process.stdout.columns || 0;
    if (columns <= 0) return `${coloredPrefix} ${displayValue}`;
    const max = columns - (prefix.length + 1);
    if (max <= 0) return coloredPrefix;
    if (displayValue.length <= max) return `${coloredPrefix} ${displayValue}`;
    const ellipsis = "…";
    const keep = Math.max(0, max - ellipsis.length);
    return `${coloredPrefix} ${displayValue.slice(0, keep)}${ellipsis}`;
  };

  process.stdout.write(formatLine(frames[i], currentText));
  const timer = setInterval(() => {
    i = (i + 1) % frames.length;
    process.stdout.write(`\r\x1b[K${formatLine(frames[i], currentText)}`);
  }, 120);

  let stopped = false;

  const stop = (success = true) => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    process.stdout.write(`\r\x1b[K${formatLine(success ? "✔" : "✖", currentText)}\n`);
  };

  const update = (nextText: string) => {
    if (stopped) return;
    currentText = nextText;
    process.stdout.write(`\r\x1b[K${formatLine(frames[i], currentText)}`);
  };

  const log = (line: string) => {
    const renderedLine = colorLeadingSymbol(line);
    if (stopped) {
      process.stdout.write(`${renderedLine}\n`);
      return;
    }
    process.stdout.write(`\r\x1b[K${renderedLine}\n`);
    process.stdout.write(formatLine(frames[i], currentText));
  };

  return { stop, update, log };
}
