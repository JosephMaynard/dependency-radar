#!/usr/bin/env node
import path from "path";
import { ChildProcess, spawn } from "child_process";
import { platform } from "os";
import { aggregateData } from "./aggregator";
import {
  findDependenciesByPackageName,
  formatExplainOutput,
  type ExplainAvailability,
} from "./explain";
import { runImportGraph } from "./runners/importGraphRunner";
import { runPackageAudit } from "./runners/npmAudit";
import { runNpmLs } from "./runners/npmLs";
import { runPackageOutdated } from "./runners/npmOutdated";
import { enrichAggregatedWithRegistryMetadata } from "./runners/npmRegistryMetadata";
import { enrichAggregatedWithMaintenanceSignals, resolveRegistryBaseUrl } from "./runners/maintenanceSignals";
import { runLockfileSupplyChainSignals } from "./runners/lockfileSignals";
import { renderReport } from "./report";
import { compareReports, formatCompareOutput } from "./compare";
import { buildDependencyFindings } from "./findings";
import { applyUpgradeRisk } from "./upgradeRisk";
import {
  defaultOutputName,
  renderCycloneDx,
  renderSarif,
  renderSpdx,
  type ReportFormat,
} from "./outputFormats";
import { formatWhyOutput } from "./why";
import { COMPATIBLE_BASELINE_SCHEMA_VERSIONS, REPORT_SCHEMA_VERSION, renderReportJsonSchema } from "./schema";
import {
  SUPPORTED_FAIL_ON_RULES,
  evaluateComparePolicyViolations,
  evaluatePolicyViolations,
  parseFailOnRules,
} from "./failOn";
import type { FailOnRule, PolicyViolation } from "./failOn";
import type {
  AggregatedData,
  OutdatedEntry,
  OutdatedResult,
  ScanCollectorName,
  ScanCollectorStatus,
  ScanStatus,
  ToolResult,
  WorkspacePackage,
} from "./types";
import fs from "fs/promises";
import { ensureDir, getDependencyRadarVersion, removeDir, runCommand, pathExists } from "./utils";

const EXIT_POLICY_VIOLATION = 1;
const EXIT_USAGE_OR_INCOMPLETE = 2;

// Workspace detection and helpers
type WorkspaceType = "pnpm" | "npm" | "yarn" | "bun" | "none";
type PackageManager = "npm" | "pnpm" | "yarn" | "bun";

interface WorkspaceDiscovery {
  type: WorkspaceType;
  packagePaths: string[]; // absolute paths
  pnpmWorkspaceOverrides?: Record<string, unknown>;
}

type OutdatedAttempt = {
  attempted: boolean;
  result?: ToolResult<any>;
};

const skippedToolResult: ToolResult<any> = {
  ok: true,
  status: "skipped",
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
  if (raw.startsWith("bun@") || raw === "bun") return "bun";
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
  if ((await pathExists(path.join(projectPath, "bun.lock"))) || (await pathExists(path.join(projectPath, "bun.lockb")))) return "bun";
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
  if (fallback === "bun" && ((await pathExists(path.join(projectPath, "bun.lock"))) || (await pathExists(path.join(projectPath, "bun.lockb"))))) return "bun";
  if (await pathExists(path.join(projectPath, "pnpm-lock.yaml"))) return "pnpm";
  if (await pathExists(path.join(projectPath, "yarn.lock"))) return "yarn";
  if ((await pathExists(path.join(projectPath, "bun.lock"))) || (await pathExists(path.join(projectPath, "bun.lockb")))) return "bun";
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
  return trimmed.startsWith("workspace:");
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

type AuditMergeInput = { data: any; contextPath: string };

function mergeAuditResults(results: Array<AuditMergeInput | undefined>): any | undefined {
  const defined = results.filter((entry): entry is AuditMergeInput => Boolean(entry));
  if (defined.length === 0) return undefined;
  const base: any = {};
  const absoluteAuditNodes = (nodes: unknown, contextPath: string): string[] => {
    if (!Array.isArray(nodes)) return [];
    return Array.from(new Set(nodes
      .filter((node): node is string => typeof node === "string" && node.trim().length > 0)
      .map((node) => path.resolve(contextPath, node.trim()))));
  };

  for (const [resultIndex, entry] of defined.entries()) {
    const r = entry.data;
    if (!r || typeof r !== "object") continue;
    // npm audit v7+ shape: { vulnerabilities: {..} }
    if (r.vulnerabilities && typeof r.vulnerabilities === "object") {
      base.vulnerabilities = base.vulnerabilities || {};
      const vulnerabilityEntries = Object.entries<any>(r.vulnerabilities);
      const mergedKeys = new Map(
        vulnerabilityEntries.map(([key]) => [key, `${resultIndex}:${key}`]),
      );
      for (const [k, v] of Object.entries<any>(r.vulnerabilities)) {
        const mergedKey = mergedKeys.get(k)!;
        const normalized = {
          ...v,
          nodes: absoluteAuditNodes(v?.nodes, entry.contextPath),
          ...(Array.isArray(v?.via)
            ? {
                via: v.via.map((via: unknown) =>
                  typeof via === "string" ? mergedKeys.get(via) || via : via,
                ),
              }
            : {}),
        };
        base.vulnerabilities[mergedKey] = normalized;
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
  command: "scan" | "explain" | "compare" | "why" | "schema";
  packageName?: string;
  comparePath?: string;
  invalidCommand?: string;
  commandProvided: boolean;
  project: string;
  quiet: boolean;
  out: string;
  keepTemp: boolean;
  audit: boolean;
  outdated: boolean;
  maintenance: boolean;
  json: boolean;
  open: boolean;
  noReport: boolean;
  failOn: Set<FailOnRule>;
  format: ReportFormat;
  targetNodeMajor?: number;
  auditSignatures: boolean;
  schema: boolean;
  outProvided: boolean;
  timestamp: boolean;
  strict: boolean;
}

/**
 * Parse CLI tokens and return a configured CliOptions object reflecting the requested command and flags.
 *
 * Recognizes an optional leading command (scan, explain, compare, why, schema), positional operands for
 * commands that require them (package name for explain/why, compare path for compare), and these flags:
 * --project, --quiet, --out, --keep-temp, --offline, --no-maintenance, --json, --format, --sbom,
 * --target-node, --audit-signatures, --schema, --timestamp, --open, --no-report, --fail-on, --help / -h.
 *
 * The --offline flag disables registry-backed checks. Unknown options or unexpected positional
 * arguments cause the process to exit with an error.
 *
 * @param argv - Array of CLI tokens (typically process.argv.slice(2))
 * @returns The resolved CliOptions with defaults applied and values overridden by argv
 */
function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    command: "scan",
    commandProvided: false,
    project: process.cwd(),
    quiet: false,
    out: "dependency-radar.html",
    keepTemp: false,
    audit: true,
    outdated: true,
    maintenance: true,
    json: false,
    open: false,
    noReport: false,
    failOn: new Set<FailOnRule>(),
    format: "html",
    auditSignatures: false,
    schema: false,
    outProvided: false,
    timestamp: false,
    strict: false,
  };

  const args = [...argv];
  if (args[0] && !args[0].startsWith("-")) {
    const command = args.shift()!;
    if (command === "scan" || command === "explain" || command === "compare" || command === "why" || command === "schema") {
      opts.command = command;
      opts.commandProvided = true;
    } else {
      opts.invalidCommand = command;
      return opts;
    }
  }

  while (args.length) {
    const arg = args.shift();
    if (!arg) break;
    if (!arg.startsWith("-") && (opts.command === "explain" || opts.command === "why") && !opts.packageName) {
      opts.packageName = arg;
    }
    else if (!arg.startsWith("-") && opts.command === "compare" && !opts.comparePath) {
      opts.comparePath = arg;
    }
    else if (!arg.startsWith("-")) {
      console.error(`Unexpected argument: "${arg}".`);
      process.exit(EXIT_USAGE_OR_INCOMPLETE);
    }
    else if (arg === "--project") opts.project = takeOptionValue(args, arg, true);
    else if (arg === "--quiet") opts.quiet = true;
    else if (arg === "--out") {
      opts.out = takeOptionValue(args, arg, true);
      opts.outProvided = true;
    }
    else if (arg === "--keep-temp") opts.keepTemp = true;
    else if (arg === "--offline") {
      opts.audit = false;
      opts.outdated = false;
      opts.maintenance = false;
    }
    else if (arg === "--no-maintenance") opts.maintenance = false;
    else if (arg === "--json") {
      opts.json = true;
      opts.format = "json";
    }
    else if (arg === "--format") {
      const format = takeOptionValue(args, arg);
      if (!isReportFormat(format)) {
        console.error(`Unknown --format: "${format}". Supported formats: html, json, sarif, cyclonedx, spdx.`);
        process.exit(EXIT_USAGE_OR_INCOMPLETE);
      }
      opts.format = format;
      opts.json = format === "json";
    }
    else if (arg === "--sbom") {
      const format = takeOptionValue(args, arg);
      if (format !== "cyclonedx" && format !== "spdx") {
        console.error('Unknown --sbom format. Supported formats: cyclonedx, spdx.');
        process.exit(EXIT_USAGE_OR_INCOMPLETE);
      }
      opts.format = format;
    }
    else if (arg === "--target-node") {
      const value = Number.parseInt(takeOptionValue(args, arg), 10);
      if (!Number.isFinite(value) || value <= 0) {
        console.error("--target-node must be a positive Node.js major version.");
        process.exit(EXIT_USAGE_OR_INCOMPLETE);
      }
      opts.targetNodeMajor = value;
    }
    else if (arg === "--audit-signatures") opts.auditSignatures = true;
    else if (arg === "--schema") opts.schema = true;
    else if (arg === "--timestamp") opts.timestamp = true;
    else if (arg === "--strict") opts.strict = true;
    else if (arg === "--version" || arg === "-V") {
      console.log(getDependencyRadarVersion());
      process.exit(0);
    }
    else if (arg === "--open") opts.open = true;
    else if (arg === "--no-report") opts.noReport = true;
    else if (arg === "--fail-on") {
      const value = args.shift();
      if (!value) {
        console.error(
          "Missing value for --fail-on. Provide a comma-separated list of rules.",
        );
        process.exit(EXIT_USAGE_OR_INCOMPLETE);
      }
      let rules: Set<FailOnRule>;
      try {
        rules = parseFailOnRules(value);
      } catch (err: any) {
        console.error(
          err instanceof Error ? err.message : "Invalid --fail-on rules.",
        );
        process.exit(EXIT_USAGE_OR_INCOMPLETE);
        return opts;
      }
      for (const rule of rules) {
        opts.failOn.add(rule);
      }
    }
    else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
    else {
      console.error(`Unknown option: "${arg}".`);
      process.exit(EXIT_USAGE_OR_INCOMPLETE);
    }
  }

  return opts;
}

/**
 * Extracts and returns the next CLI token as the value for a given option, consuming it from `args`.
 *
 * @param args - Remaining argv tokens; the first element will be removed and returned.
 * @param option - The option name shown in the error message when a value is missing.
 * @param allowLeadingDash - When `true`, permit values that begin with `-`; otherwise treat such tokens as missing values.
 * @returns The consumed option value.
 * @remarks Exits the process with code 1 and prints an error if no valid value is present.
 */
function takeOptionValue(args: string[], option: string, allowLeadingDash = false): string {
  const value = args[0];
  if (!value || (!allowLeadingDash && value.startsWith("-"))) {
    console.error(`Missing value for ${option}.`);
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
  }
  return args.shift()!;
}

/**
 * Checks whether a string is a supported report format.
 *
 * @param value - The string to test
 * @returns `true` if `value` is one of `html`, `json`, `sarif`, `cyclonedx`, or `spdx`, `false` otherwise.
 */
function isReportFormat(value: string): value is ReportFormat {
  return value === "html" || value === "json" || value === "sarif" || value === "cyclonedx" || value === "spdx";
}

/**
 * Formats a numeric date/time component as a two-digit string.
 *
 * @param value - The numeric part (e.g., day, month, hour, or minute) to format
 * @returns The value as a two-character string, padded with a leading zero when needed
 */
function padDatePart(value: number): string {
  return String(value).padStart(2, "0");
}

/**
 * Formats a Date into a filesystem-safe timestamp string suitable for filenames.
 *
 * @param date - The date to format (local time is used).
 * @returns A string in the form `YYYY-MM-DD_HH-MM-SS` (zero-padded). 
 */
function formatFilenameTimestamp(date: Date): string {
  return [
    date.getFullYear(),
    padDatePart(date.getMonth() + 1),
    padDatePart(date.getDate()),
  ].join("-") + "_" + [
    padDatePart(date.getHours()),
    padDatePart(date.getMinutes()),
    padDatePart(date.getSeconds()),
  ].join("-");
}

/**
 * Insert a local timestamp into the filename portion of an output path.
 *
 * If the path has a file extension, the timestamp is inserted before the extension;
 * otherwise the timestamp is appended to the filename. The directory portion is preserved.
 *
 * @param outputPath - The file path whose filename will receive the timestamp
 * @param date - Date to derive the timestamp from; defaults to the current date/time
 * @returns The input path with a timestamp embedded into the filename, preserving directory and extension
 */
function addTimestampToOutputPath(outputPath: string, date = new Date()): string {
  const parsed = path.parse(outputPath);
  const timestamp = formatFilenameTimestamp(date);
  const basename = parsed.ext
    ? `${parsed.name}.${timestamp}${parsed.ext}`
    : `${parsed.name}.${timestamp}`;
  return path.join(parsed.dir, basename);
}

/**
 * Determines whether the given package manager uses registry-based collectors.
 *
 * @returns `true` if the manager is `npm`, `pnpm`, or `yarn`, `false` otherwise.
 */
function supportsRegistryCollectors(manager: PackageManager): manager is "npm" | "pnpm" | "yarn" {
  return manager === "npm" || manager === "pnpm" || manager === "yarn";
}

/**
 * Print the CLI usage and available options to the console.
 *
 * Displays the command synopsis and descriptions for supported flags including
 * --project, --out, --json, --timestamp, --no-report, --keep-temp, --offline, --open, and --fail-on.
 */
function printHelp(): void {
  console.log(`dependency-radar [scan] [options]
dependency-radar explain <package-name> [options]
dependency-radar why <package-name> [options]
dependency-radar compare <previous dependency-radar.json> [options]

If no command is provided, \`scan\` is run by default.

Options:
  --project <path>   Project folder (default: cwd)
  --quiet            Suppress progress/info logs but keep summary and failures
  --out <path>       Output file (default depends on format)
  --format <format>  Output format: html, json, sarif, cyclonedx, spdx
  --sbom <format>    Write an SBOM: cyclonedx or spdx
  --target-node <n>  Add Node major compatibility findings
  --audit-signatures Verify npm registry signatures/provenance (opt-in, online only)
  --schema           Print JSON schema, or write it when --out is provided
  --json             Write aggregated data to JSON (default filename: dependency-radar.json)
  --timestamp        Add a local timestamp to generated report filenames
  --strict           Exit 2 when an enabled collector is incomplete or unavailable
  --version, -V      Print the Dependency Radar version
  --no-report        Do not write HTML/JSON report files or temp artifacts to disk
  --keep-temp        Keep .dependency-radar folder
  --offline          Skip registry-backed checks (audit, outdated, signatures, maintenance signals, targeted registry enrichment)
  --no-maintenance   Skip registry maintenance signals (deprecated/unmaintained/archived checks)
  --open             Open the generated report using the system default application
  --fail-on <rules>  Fail with exit code 1 when selected rules are violated
                     Scan rules: directly-imported-vuln, production-vuln, high-severity-vuln,
                                 licence-mismatch, copyleft-detected, unknown-licence,
                                 supply-chain-source, supply-chain-combo,
                                 deprecated-dependency, unmaintained-dependency
                     Alias: reachable-vuln (deprecated; means directly-imported-vuln)
                     Compare rules: new-deprecated, new-supply-chain-signal,
                                    new-install-script, new-native-binding, new-bin,
                                    new-direct-dependency, new-child-process,
                                    new-network-access, new-env-access, new-home-access,
                                    new-ssh-usage, new-obfuscation-signal,
                                    new-bundled-dependencies, new-shrinkwrap,
                                    new-recent-package, new-recent-version,
                                    new-low-release-history, new-reactivated-package,
                                    new-old-major-patch

\`explain\` reuses the same local scan model and prints a terminal view for one package.
\`why\` prints shortest dependency paths for one package.
\`compare\` scans the current project and compares it with a previous JSON report.
`);
}

/**
 * Attempts to open the given file in the system's default application.
 *
 * Spawns a detached OS-specific opener process (so the function returns immediately). If the spawn fails, a warning is logged to the console.
 *
 * @param filePath - Path (absolute or relative) to the file to open
 */
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
      // Avoid `cmd /c start`: cmd re-parses its arguments, so metacharacters
      // in the report path (&, ^, %VAR%) would be interpreted as shell
      // syntax. rundll32's FileProtocolHandler opens the default handler
      // without any shell parsing.
      child = spawn("rundll32", ["url.dll,FileProtocolHandler", normalizedPath], {
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

/**
 * Determine whether ANSI color output should be enabled for the current process.
 *
 * Considers the `NO_COLOR` and `FORCE_COLOR` environment variables and falls back to whether `stdout` is a TTY.
 *
 * @returns `true` if ANSI color output should be enabled, `false` otherwise.
 */
function shouldUseColor(): boolean {
  if (process.env.NO_COLOR !== undefined) return false;
  const forceColor = process.env.FORCE_COLOR;
  if (forceColor === "0") return false;
  if (forceColor !== undefined) return true;
  return Boolean(process.stdout.isTTY);
}

const COLOR_ENABLED = shouldUseColor();

function supportsTerminalHyperlinks(): boolean {
  if (!process.stdout.isTTY) return false;
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.TERM === "dumb") return false;
  return true;
}

function formatTerminalLink(label: string, url: string): string {
  if (!supportsTerminalHyperlinks()) return label;
  return `\u001B]8;;${url}\u0007${label}\u001B]8;;\u0007`;
}

/**
 * Wraps text with ANSI color or style escape sequences when terminal coloring is enabled.
 *
 * @param value - The text to style
 * @param color - The style to apply; one of `'bold'`, `'green'`, `'red'`, `'yellow'`, or `'cyan'`
 * @returns The input string wrapped with the selected ANSI escape codes if colors are enabled, otherwise the original `value`
 */
function styleText(
  value: string,
  color: "bold" | "green" | "red" | "yellow" | "cyan",
): string {
  if (!COLOR_ENABLED) return value;
  return `${ANSI[color]}${value}${ANSI.reset}`;
}

/**
 * Extracts the first Unicode character from a string and the remaining substring.
 *
 * @param value - The input string to split
 * @returns An object with `head` set to the first character (empty string if input is empty) and `tail` set to the remainder of the string after `head`
 */
function splitFirstGlyph(value: string): { head: string; tail: string } {
  const chars = Array.from(value);
  const head = chars[0] || "";
  const tail = value.slice(head.length);
  return { head, tail };
}

/**
 * Apply ANSI color styling to recognized status glyphs at the start of a string.
 *
 * Recognized leading glyphs are colored as follows: "✔" → green, "✖" → red, "⚠" → yellow,
 * "↗", "ℹ", "📦" → cyan, and "📉" → yellow. If the first grapheme is not one of these,
 * the input is returned unchanged.
 *
 * @param symbol - The string whose leading glyph should be colorized (if recognized)
 * @returns The input string with the leading glyph wrapped in color styling when recognized, otherwise the original string
 */
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

/**
 * Applies ANSI color styling to a leading status glyph in a text line when present.
 *
 * @param line - The input line; if it starts with a recognized status glyph (e.g., ✔, ✖, ⚠, ↗, ℹ, 📦, 📉), that glyph will be replaced with its colored equivalent.
 * @returns The line with the leading glyph colorized when applicable, or the original line unchanged.
 */
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

/**
 * Format a CLI status line with a colored leading symbol and message.
 *
 * @param symbol - The single-character or glyph to display as the leading symbol
 * @param message - The text message that follows the symbol
 * @returns The formatted status line with the colored symbol, a single separating space, and the message
 */
function statusLine(symbol: string, message: string): string {
  return `${colorSymbol(symbol)} ${message}`;
}

type CliSummary = {
  directDeps: number;
  transitiveDeps: number;
  vulnerablePackages: number;
  directlyImportedVulnerablePackages: number;
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

/**
 * Print policy violation messages to stdout as a human-readable list when any exist.
 *
 * @param violations - An array of policy violations to display; each violation's `message` will be printed as a list item. If the array is empty, nothing is printed.
 */
function printPolicyViolations(violations: PolicyViolation[]): void {
  if (violations.length === 0) return;
  console.log("");
  console.log(colorLeadingSymbol("✖ Policy violations detected:"));
  for (const violation of violations) {
    console.log(`- ${violation.message}`);
    for (const detail of violation.details || []) {
      console.log(`  - ${detail}`);
    }
  }
}

/**
 * Produce a concise CLI summary from aggregated workspace data.
 *
 * @param aggregated - Aggregated workspace data produced by the scan
 * @param options.importGraphComplete - `true` when import graph collection completed for all packages; affects unused dependency counting
 * @returns An object with:
 * - `directDeps`: number of direct dependencies in the workspace
 * - `transitiveDeps`: number of transitive dependencies in the workspace
 * - `vulnerablePackages`: count of dependencies with at least one reported vulnerability
 * - `directlyImportedVulnerablePackages`: count of vulnerable dependencies referenced by direct static imports
 * - `unusedInstalledDeps`: count of direct runtime dependencies that appear unused (only when `importGraphComplete` is `true`)
 * - `licenseMismatches`: count of dependencies whose license status is `mismatch`
 * - `majorUpgradeBlockers`: count of dependencies that have one or more upgrade blockers
 * - `majorUpgradeBlockerBreakdown`: object with counts for specific blocker types (`peerDependency`, `nodeEngine`, `deprecated`, `nativeBindings`, `installScripts`)
 */
function buildCliSummary(
  aggregated: AggregatedData,
  options: { importGraphComplete: boolean },
): CliSummary {
  let vulnerablePackages = 0;
  let directlyImportedVulnerablePackages = 0;
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
        directlyImportedVulnerablePackages += 1;
      }
    }
    // Count "unused" only when import graph collection succeeded for all packages.
    // `importUsage` is an optional object (or undefined), not a boolean/string state.
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
    directlyImportedVulnerablePackages,
    unusedInstalledDeps,
    licenseMismatches,
    majorUpgradeBlockers,
    majorUpgradeBlockerBreakdown,
  };
}

/**
 * Choose the correct singular or plural form based on a numeric count.
 *
 * @param value - The numeric count that determines which form to use
 * @param singular - The singular form to use when `value` equals 1
 * @param plural - The plural form to use for any other `value`
 * @returns The `singular` string if `value` is 1, `plural` otherwise
 */
function pluralize(value: number, singular: string, plural: string): string {
  return value === 1 ? singular : plural;
}

/**
 * Print a concise, human-readable CLI summary of scan results to standard output.
 *
 * @param summary - Aggregated counts and breakdowns (dependencies, vulnerabilities, unused deps, license mismatches, and major-upgrade blocker details) used to compose the printed summary
 */
function printCliSummary(summary: CliSummary): void {
  const bullet = "•";
  console.log("");
  console.log("Summary:");
  console.log(`${bullet} Direct dependencies scanned: ${summary.directDeps}`);
  console.log(`${bullet} Transitive dependencies scanned: ${summary.transitiveDeps}`);
  console.log(
    `${bullet} Vulnerable packages: ${summary.vulnerablePackages} (${summary.directlyImportedVulnerablePackages} directly imported)`,
  );
  console.log(`${bullet} Dependencies with no static import reference: ${summary.unusedInstalledDeps}`);
  console.log(`${bullet} License mismatches: ${summary.licenseMismatches}`);
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

function formatLabel(format: ReportFormat): string {
  if (format === "html") return "Report";
  if (format === "json") return "JSON";
  if (format === "sarif") return "SARIF";
  if (format === "cyclonedx") return "CycloneDX SBOM";
  return "SPDX SBOM";
}

type CollectorAvailability = {
  audit: ExplainAvailability;
  importGraphComplete: boolean;
};

function collectorStatusFromResults(
  results: Array<ToolResult<any> | undefined>,
  enabled: boolean,
): ScanCollectorStatus {
  if (!enabled) return "skipped";
  const present = results.filter((result): result is ToolResult<any> => Boolean(result));
  if (present.length === 0 || present.every((result) => result.status === "skipped")) return "skipped";
  const available = present.filter((result) => result.ok && result.status !== "skipped").length;
  if (available === present.length) return "available";
  return available > 0 ? "partial" : "unavailable";
}

function requiredCollectorsForRule(rule: FailOnRule): ScanCollectorName[] {
  if (rule === "directly-imported-vuln" || rule === "reachable-vuln") {
    return ["dependencyTree", "audit", "imports"];
  }
  if (rule === "production-vuln" || rule === "high-severity-vuln") {
    return ["dependencyTree", "audit"];
  }
  if (rule === "supply-chain-source" || rule === "new-supply-chain-signal") {
    return ["supplyChain"];
  }
  if (rule === "supply-chain-combo") {
    // Needs both the lockfile source signals and the dependency records that
    // carry install-hook evidence.
    return ["dependencyTree", "supplyChain"];
  }
  if (rule === "deprecated-dependency" || rule === "unmaintained-dependency" || rule === "new-deprecated") {
    return ["dependencyTree", "maintenance"];
  }
  if (
    rule === "new-recent-package" ||
    rule === "new-recent-version" ||
    rule === "new-low-release-history" ||
    rule === "new-reactivated-package" ||
    rule === "new-old-major-patch"
  ) {
    return ["dependencyTree", "registryMetadata"];
  }
  return ["dependencyTree"];
}

function incompleteEvidenceReasons(
  scanStatus: ScanStatus,
  rules: Set<FailOnRule>,
  strict: boolean,
): string[] {
  const reasons = new Set<string>();
  for (const rule of rules) {
    for (const collector of requiredCollectorsForRule(rule)) {
      const status = scanStatus.collectors[collector];
      if (status !== "available") {
        reasons.add(`${collector} evidence is ${status} but is required by --fail-on ${rule}`);
      }
    }
  }
  if (strict) {
    for (const [collector, status] of Object.entries(scanStatus.collectors) as Array<[ScanCollectorName, ScanCollectorStatus]>) {
      if (status === "partial" || status === "unavailable") {
        reasons.add(`${collector} collection is ${status} (--strict)`);
      }
    }
  }
  return Array.from(reasons);
}

function printIncompleteEvidence(reasons: string[]): void {
  if (reasons.length === 0) return;
  console.error("\nScan evidence is incomplete:");
  for (const reason of reasons) console.error(`  - ${reason}`);
}

type AnalysisExecutionResult = {
  aggregated: AggregatedData;
  summary: CliSummary;
  policyViolations: PolicyViolation[];
  dependencyCount: number;
  elapsedSeconds: string;
  outputCreated: boolean;
  outputPath: string;
  shouldWriteArtifacts: boolean;
  collectorAvailability: CollectorAvailability;
  incompleteReasons: string[];
  workspace: WorkspaceDiscovery;
  packagePaths: string[];
};

/**
 * Run a full dependency analysis for a project/workspace and return the aggregated results.
 *
 * Performs workspace detection, per-package collection (audit, dependency trees, import graphs, outdated), merges collected data, runs aggregation and policy evaluation, and optionally writes report artifacts to disk. May create a temporary directory under the project (projectPath/.dependency-radar) and will remove it unless `opts.keepTemp` is set.
 *
 * @param opts - CLI-resolved options controlling project path, enabled collectors (audit/outdated), artifact format/output, reporting flags, and policy rules.
 * @param options.shouldWriteArtifacts - If true, write report artifacts (JSON/HTML/SBOM) to the resolved output path.
 * @param options.emitArtifactSummary - If true, print a summary line about artifact creation to stdout.
 * @param options.emitWorkspacePackageSummary - If true, print a brief workspace package summary when a workspace is detected.
 * @returns An AnalysisExecutionResult containing the aggregated report, CLI summary, policy violations, dependency counts, timing, output path/creation status, collector availability, and workspace metadata.
 */
async function executeAnalysis(
  opts: CliOptions,
  options: {
    shouldWriteArtifacts: boolean;
    emitArtifactSummary: boolean;
    emitWorkspacePackageSummary: boolean;
  },
): Promise<AnalysisExecutionResult> {
  const shouldWriteArtifacts = options.shouldWriteArtifacts;
  const projectPath = path.resolve(opts.project);
  let outputPath = opts.outProvided
    ? path.resolve(opts.out)
    : path.resolve(projectPath, opts.out);
  const startTime = Date.now();
  let dependencyCount = 0;
  let outputCreated = false;

  if (opts.command === "scan" && opts.noReport && opts.keepTemp && !opts.quiet) {
    console.log(
      statusLine("⚠", "--keep-temp is ignored when --no-report is enabled."),
    );
  }
  if (!opts.outProvided && opts.format !== "html") {
    opts.out = defaultOutputName(opts.format);
    outputPath = path.resolve(projectPath, opts.out);
  }

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
          defaultOutputName(opts.format),
        );
      }
    } catch {
      // ignore, best-effort path normalization
    }
    if (opts.timestamp) {
      outputPath = addTimestampToOutputPath(outputPath);
    }
  }

  const tempDir = path.join(projectPath, ".dependency-radar");

  const workspace = await detectWorkspace(projectPath);
  const yarnPnP = await detectYarnPnP(projectPath);
  if (workspace.type === "yarn" && workspace.packagePaths.length === 0) {
    if (!opts.quiet) {
      console.log(statusLine("⚠", "Yarn Plug'n'Play detected; using the root package and yarn.lock where possible."));
    }
    workspace.packagePaths = [projectPath];
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
      ? " Yarn Plug'n'Play appears enabled; lockfile graph data will be used where possible, but package metadata from zip/cache files is not crawled in this release."
      : "";
    console.warn(
      colorLeadingSymbol(
        `⚠ node_modules was not found at ${projectPath}. Scan completeness may be reduced for this ${workspaceHint}. Run your package manager install before scanning when local package metadata is required.${yarnHint}`,
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
  const bunVersion = await getToolVersion("bun", projectPath);
  const toolVersions = compactToolVersions({
    npm: npmVersion,
    pnpm: pnpmVersion,
    yarn: yarnVersion,
    bun: bunVersion,
  });
  const packageManagerVersion =
    scanManager === "npm"
      ? npmVersion
      : scanManager === "pnpm"
        ? pnpmVersion
        : scanManager === "yarn"
          ? yarnVersion
          : bunVersion;
  if (!opts.quiet && packageManager === "yarn" && yarnPnP) {
    console.log(statusLine("⚠", "Yarn Plug'n'Play detected; using lockfile-derived graph data where available."));
  }

  const packagePaths = workspace.packagePaths;
  const workspaceLabel =
    workspace.type === "none"
      ? "Single project"
      : `${workspace.type.toUpperCase()} workspace`;
  if (!opts.quiet) {
    console.log(statusLine("✔", `${workspaceLabel} detected`));
  }
  if (!opts.quiet && workspace.type !== "none" && scanManager !== workspace.type) {
    console.log(
      statusLine(
        "✔",
        `Using ${scanManager.toUpperCase()} for dependency data (lockfile detected)`,
      ),
    );
  }

  const spinner = createProgressReporter(
    `Scanning ${workspaceLabel} at ${projectPath}`,
    opts.quiet,
  );
  try {
    if (shouldWriteArtifacts) {
      await ensureDir(tempDir);
    }

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
    const configuredRegistry = await resolveRegistryBaseUrl(projectPath);
    let configuredRegistryHost: string | undefined;
    try {
      configuredRegistryHost = new URL(configuredRegistry).host.toLowerCase();
    } catch {
      configuredRegistryHost = undefined;
    }
    const supplyChainResult = await runLockfileSupplyChainSignals(projectPath, tempDir, {
      persistToDisk: shouldWriteArtifacts,
      auditSignatures: opts.auditSignatures,
      offline: !opts.audit,
      ...(configuredRegistryHost ? { expectedRegistryHosts: [configuredRegistryHost] } : {}),
    }).catch((err) => ({ ok: false, error: String(err) }) as ToolResult<any>);

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
        && supportsRegistryCollectors(scanManager)
          ? runPackageAudit(
              meta.path,
              pkgTempDir,
              scanManager,
              yarnVersion,
              { persistToDisk: shouldWriteArtifacts },
            ).catch(
              (err) => ({ ok: false, error: String(err) }) as ToolResult<any>,
            )
          : Promise.resolve(opts.audit ? skippedToolResult : undefined),
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
        && supportsRegistryCollectors(scanManager)
          ? runPackageOutdated(
              meta.path,
              pkgTempDir,
              scanManager,
              { persistToDisk: shouldWriteArtifacts },
            ).catch(
              (err) => ({ ok: false, error: String(err) }) as ToolResult<any>,
            )
          : Promise.resolve(opts.outdated ? skippedToolResult : undefined),
      ]);
      perPackageAudit.push(a);
      perPackageLs.push(l);
      perPackageImportGraph.push(ig);
      perPackageOutdated.push({ attempted: Boolean(opts.outdated), result: o });
    }

    if (opts.audit) {
      const auditOk = perPackageAudit.every((r) => r && r.ok);
      const auditSkipped = perPackageAudit.every((r) => r?.status === "skipped");
      if (!opts.quiet || !auditOk) {
        spinner.log(
          statusLine(
            auditSkipped ? "ℹ" : auditOk ? "✔" : "✖",
            `${scanManager.toUpperCase()} audit data ${auditSkipped ? "skipped" : auditOk ? "collected" : "unavailable"}`,
          ),
        );
      }
    }
    if (opts.auditSignatures && !opts.quiet) {
      const audit = supplyChainResult.ok ? supplyChainResult.data?.signatureAudit : undefined;
      if (audit?.status === "skipped") {
        spinner.log(statusLine("⚠", "npm audit signatures skipped (--offline)"));
      } else {
        spinner.log(statusLine(audit?.ok ? "✔" : "✖", `npm audit signatures ${audit?.ok ? "verified" : "unavailable"}`));
      }
    }
    if (opts.outdated) {
      const outdatedOk = perPackageOutdated.every(
        (r) => r.result && r.result.ok,
      );
      const outdatedSkipped = perPackageOutdated.every(
        (r) => r.result?.status === "skipped",
      );
      if (!opts.quiet || !outdatedOk) {
        spinner.log(
          statusLine(
            outdatedSkipped ? "ℹ" : outdatedOk ? "✔" : "✖",
            `${scanManager.toUpperCase()} outdated data ${outdatedSkipped ? "skipped" : outdatedOk ? "collected" : "unavailable"}`,
          ),
        );
      }
    }

    const mergedAuditData = mergeAuditResults(
      perPackageAudit.map((r, index) => (r && r.ok && r.data
        ? {
            data: r.data,
            contextPath: r.contextPath || packageMetas[index].path,
          }
        : undefined)),
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
    const auditCollectorStatus = collectorStatusFromResults(perPackageAudit, opts.audit);
    let dependencyTreeCollectorStatus = collectorStatusFromResults(perPackageLs, true);
    const importCollectorStatus = collectorStatusFromResults(perPackageImportGraph, true);
    const signatureAuditOk = !opts.auditSignatures
      || (supplyChainResult.ok && supplyChainResult.data?.signatureAudit?.ok === true);
    const supplyChainCollectorStatus: ScanCollectorStatus = supplyChainResult.ok && signatureAuditOk
      ? "available"
      : "unavailable";
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

    const aggregated = await aggregateData({
      projectPath,
      auditResult,
      npmLsResult,
      importGraphResult,
      outdatedResult,
      supplyChainResult,
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
      ...(typeof opts.targetNodeMajor === "number" ? { targetNodeMajor: opts.targetNodeMajor } : {}),
    });

    let enrichmentTouchedData = false;
    let registryMetadataCollectorStatus: ScanCollectorStatus = opts.outdated ? "available" : "skipped";
    if (opts.outdated) {
      let registryEnrichment = { attempted: 0, succeeded: 0 };
      try {
        registryEnrichment = await enrichAggregatedWithRegistryMetadata(aggregated, {
          offline: false,
        });
      } catch (err) {
        registryMetadataCollectorStatus = "unavailable";
        if (!opts.quiet) {
          const message = err instanceof Error ? err.message : String(err);
          spinner.log(statusLine("⚠", `Targeted registry metadata unavailable (${message})`));
        }
      }
      if (registryMetadataCollectorStatus === "available" && registryEnrichment.succeeded < registryEnrichment.attempted) {
        registryMetadataCollectorStatus = "partial";
      }
      if (!opts.quiet && registryEnrichment.succeeded > 0) {
        spinner.log(statusLine("✔", `Targeted registry metadata collected for ${registryEnrichment.succeeded} suspicious package${registryEnrichment.succeeded === 1 ? "" : "s"}`));
      }
      if (registryEnrichment.attempted > 0) enrichmentTouchedData = true;
    }

    let maintenanceCollectorStatus: ScanCollectorStatus = opts.maintenance ? "available" : "skipped";
    if (opts.maintenance) {
      try {
        const budgetOverride = Number.parseInt(process.env.DEPENDENCY_RADAR_MAINTENANCE_BUDGET_MS || "", 10);
        const maintenance = await enrichAggregatedWithMaintenanceSignals(aggregated, {
          projectPath,
          ...(Number.isFinite(budgetOverride) ? { budgetMs: budgetOverride } : {}),
        });
        if (
          maintenance.truncatedNames > 0 ||
          maintenance.succeeded + maintenance.fromCache < maintenance.checkedNames
        ) {
          maintenanceCollectorStatus = "partial";
        }
        if (maintenance.checkedNames > 0) {
          enrichmentTouchedData = true;
          if (!opts.quiet) {
            const flagged = [
              maintenance.deprecatedNames > 0 ? `${maintenance.deprecatedNames} deprecated` : undefined,
              maintenance.archivedNames > 0 ? `${maintenance.archivedNames} archived` : undefined,
              maintenance.unmaintainedNames > 0 ? `${maintenance.unmaintainedNames} unmaintained` : undefined,
              maintenance.fromCache > 0 ? `${maintenance.fromCache} from cache` : undefined,
            ].filter(Boolean).join(", ");
            spinner.log(statusLine("✔", `Maintenance signals: ${maintenance.checkedNames} package${maintenance.checkedNames === 1 ? "" : "s"} checked${flagged ? ` (${flagged})` : ""}`));
            if (maintenance.truncatedNames > 0) {
              spinner.log(statusLine("⚠", `Maintenance signals skipped ${maintenance.truncatedNames} package name${maintenance.truncatedNames === 1 ? "" : "s"} beyond the lookup cap`));
            }
          }
        }
      } catch (err) {
        maintenanceCollectorStatus = "unavailable";
        if (!opts.quiet) {
          const message = err instanceof Error ? err.message : String(err);
          spinner.log(statusLine("⚠", `Maintenance signals unavailable (${message})`));
        }
      }
    }

    if (enrichmentTouchedData) {
      applyUpgradeRisk(aggregated);
      const findings = buildDependencyFindings(aggregated, { targetNodeMajor: opts.targetNodeMajor });
      aggregated.findings = findings;
      aggregated.summary.findingCount = findings.length;
    }

    dependencyCount = Object.keys(aggregated.dependencies).length;
    if (!hasProjectNodeModules && !yarnPnP && dependencyTreeCollectorStatus === "available") {
      dependencyTreeCollectorStatus = "partial";
    }
    const collectors: ScanStatus["collectors"] = {
      dependencyTree: dependencyTreeCollectorStatus,
      audit: auditCollectorStatus,
      imports: importCollectorStatus,
      maintenance: maintenanceCollectorStatus,
      registryMetadata: registryMetadataCollectorStatus,
      supplyChain: supplyChainCollectorStatus,
    };
    const scanWarnings: string[] = [];
    const addCollectorWarning = (collector: ScanCollectorName, label: string, consequence: string): void => {
      const status = collectors[collector];
      if (status !== "available") scanWarnings.push(`${label} is ${status}; ${consequence}`);
    };
    addCollectorWarning("dependencyTree", "Dependency tree collection", "dependency coverage and classification may be incomplete.");
    addCollectorWarning("audit", "Vulnerability audit", "vulnerability status is unknown.");
    addCollectorWarning("imports", "Static import collection", "direct-import evidence may be incomplete.");
    addCollectorWarning("maintenance", "Maintenance collection", "maintenance status may be incomplete.");
    addCollectorWarning("registryMetadata", "Targeted registry metadata", "registry risk signals may be incomplete.");
    addCollectorWarning("supplyChain", "Lockfile supply-chain collection", "source and integrity signals may be incomplete.");
    const scanStatus: ScanStatus = {
      complete: Object.values(collectors).every((status) => status !== "partial" && status !== "unavailable"),
      collectors,
      warnings: scanWarnings,
    };
    aggregated.scanStatus = scanStatus;
    const importGraphComplete = importCollectorStatus === "available";
    const summary = buildCliSummary(aggregated, {
      importGraphComplete,
    });
    const policyViolations = evaluatePolicyViolations(aggregated, opts.failOn);
    const incompleteReasons = incompleteEvidenceReasons(scanStatus, opts.failOn, opts.strict);

    if (!opts.quiet && options.emitWorkspacePackageSummary && workspace.type !== "none") {
      console.log(
        `Detected ${workspace.type.toUpperCase()} workspace with ${packagePaths.length} package${packagePaths.length === 1 ? "" : "s"}.`,
      );
    }

    if (shouldWriteArtifacts && (dependencyCount > 0 || scanStatus.warnings.length > 0)) {
      if (opts.format === "json") {
        await fs.mkdir(path.dirname(outputPath), { recursive: true });
        await fs.writeFile(
          outputPath,
          JSON.stringify(aggregated, null, 2),
          "utf8",
        );
      } else if (opts.format === "sarif") {
        await fs.mkdir(path.dirname(outputPath), { recursive: true });
        await fs.writeFile(outputPath, renderSarif(aggregated), "utf8");
      } else if (opts.format === "cyclonedx") {
        await fs.mkdir(path.dirname(outputPath), { recursive: true });
        await fs.writeFile(outputPath, renderCycloneDx(aggregated), "utf8");
      } else if (opts.format === "spdx") {
        await fs.mkdir(path.dirname(outputPath), { recursive: true });
        await fs.writeFile(outputPath, renderSpdx(aggregated), "utf8");
      } else {
        await renderReport(aggregated, outputPath);
      }
      outputCreated = true;
    }

    spinner.stop(true);
    const elapsedSeconds = ((Date.now() - startTime) / 1000).toFixed(1);
    if (!opts.quiet) {
      console.log(
        statusLine(
          "✔",
          `Scan complete: ${dependencyCount} dependencies analysed in ${elapsedSeconds}s`,
        ),
      );
    }

    if (!opts.quiet && options.emitArtifactSummary) {
      if (!shouldWriteArtifacts) {
        console.log(
          statusLine("ℹ", "Report output disabled (--no-report); no report artifacts written."),
        );
      } else if (outputCreated) {
        console.log(
          statusLine("✔", `${formatLabel(opts.format)} written to ${outputPath}`),
        );
      } else {
        console.log(
          statusLine(
            "✖",
            `No dependencies were found - ${formatLabel(opts.format)} not created`,
          ),
        );
      }
    }

    return {
      aggregated,
      summary,
      policyViolations,
      dependencyCount,
      elapsedSeconds,
      outputCreated,
      outputPath,
      shouldWriteArtifacts,
      collectorAvailability: {
        audit: auditCollectorStatus === "available"
          ? "available"
          : auditCollectorStatus === "skipped"
            ? "skipped"
            : "unavailable",
        importGraphComplete,
      },
      incompleteReasons,
      workspace,
      packagePaths,
    };
  } catch (err: any) {
    spinner.stop(false);
    throw err;
  } finally {
    if (shouldWriteArtifacts) {
      if (!opts.keepTemp) {
        await removeDir(tempDir);
      } else if (!opts.quiet) {
        console.log(statusLine("✔", `Temporary data kept at ${tempDir}`));
      }
    }
  }
}

async function runScanCommand(opts: CliOptions): Promise<void> {
  const result = await executeAnalysis(opts, {
    shouldWriteArtifacts: !opts.noReport,
    emitArtifactSummary: true,
    emitWorkspacePackageSummary: true,
  });

  if (!opts.quiet) {
    if (opts.open && !result.shouldWriteArtifacts) {
      console.log(statusLine("✖", "Skipping auto-open because --no-report is enabled."));
    } else if (opts.open && result.outputCreated && !isCI()) {
      console.log(
        statusLine(
          "↗",
          `Opening ${path.basename(result.outputPath)} using system default ${opts.format === "html" ? "browser" : "application"}.`,
        ),
      );
      openInBrowser(result.outputPath);
    } else if (opts.open && result.outputCreated && isCI()) {
      console.log(statusLine("✖", "Skipping auto-open in CI environment."));
    }
  }

  printCliSummary(result.summary);
  printPolicyViolations(result.policyViolations);
  printIncompleteEvidence(result.incompleteReasons);
  if (!opts.quiet) {
    console.log(
      `Docs, examples, and issue reporting: ${formatTerminalLink(
        "https://github.com/JosephMaynard/dependency-radar",
        "https://github.com/JosephMaynard/dependency-radar",
      )}`,
    );
  }

  if (result.incompleteReasons.length > 0) {
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
  }
  if (result.policyViolations.length > 0) {
    process.exit(EXIT_POLICY_VIOLATION);
  }
}

async function runExplainCommand(opts: CliOptions): Promise<void> {
  const packageName = opts.packageName?.trim();
  if (!packageName) {
    console.error("Missing package name for explain. Usage: dependency-radar explain <package-name>");
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
    return;
  }

  const result = await executeAnalysis(opts, {
    shouldWriteArtifacts: false,
    emitArtifactSummary: false,
    emitWorkspacePackageSummary: false,
  });
  const matches = findDependenciesByPackageName(result.aggregated, packageName);
  console.log("");
  console.log(
    formatExplainOutput(packageName, matches, {
      audit: result.collectorAvailability.audit,
      importGraphComplete: result.collectorAvailability.importGraphComplete,
    }),
  );

  printIncompleteEvidence(result.incompleteReasons);
  if (result.incompleteReasons.length > 0) {
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
  }

  if (matches.length === 0) {
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
  }
}

async function runWhyCommand(opts: CliOptions): Promise<void> {
  const packageName = opts.packageName?.trim();
  if (!packageName) {
    console.error("Missing package name for why. Usage: dependency-radar why <package-name>");
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
    return;
  }

  const result = await executeAnalysis(opts, {
    shouldWriteArtifacts: false,
    emitArtifactSummary: false,
    emitWorkspacePackageSummary: false,
  });
  console.log("");
  const output = formatWhyOutput(result.aggregated, packageName);
  console.log(output);
  printIncompleteEvidence(result.incompleteReasons);
  if (result.incompleteReasons.length > 0) {
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
  }
  if (output.startsWith("Package not found")) {
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
  }
}

/**
 * Compare the current analysis against a previous report and print the comparison and policy violations.
 *
 * Validates the `opts.comparePath` report file against the expected schema, runs a new analysis without
 * writing artifacts, computes a diff between the previous and current aggregated results, prints the
 * formatted comparison, prints any policy violations (including compare-specific violations), and exits
 * with code 1 when validation fails or any policy violations are present.
 *
 * @param opts - CLI options controlling the comparison run (must include `comparePath` and may include `failOn`)
 */
async function runCompareCommand(opts: CliOptions): Promise<void> {
  const previousPath = opts.comparePath?.trim();
  if (!previousPath) {
    console.error("Missing previous report path. Usage: dependency-radar compare <previous dependency-radar.json>");
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
    return;
  }
  let previous: AggregatedData;
  try {
    const parsed = JSON.parse(await fs.readFile(path.resolve(previousPath), "utf8"));
    const schemaVersion = parsed && typeof parsed === "object" ? parsed.schemaVersion : undefined;
    if (
      !parsed ||
      typeof parsed !== "object" ||
      !COMPATIBLE_BASELINE_SCHEMA_VERSIONS.includes(schemaVersion) ||
      !parsed.project ||
      !parsed.summary ||
      !parsed.dependencies ||
      typeof parsed.dependencies !== "object"
    ) {
      console.error(`Previous report schema mismatch: expected schemaVersion ${COMPATIBLE_BASELINE_SCHEMA_VERSIONS.join(", ")} (found ${schemaVersion ?? "missing"}).`);
      process.exit(EXIT_USAGE_OR_INCOMPLETE);
      return;
    }
    previous = parsed as AggregatedData;
  } catch (err: any) {
    console.error(`Could not read previous report at ${previousPath}: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
    return;
  }
  const result = await executeAnalysis(opts, {
    shouldWriteArtifacts: false,
    emitArtifactSummary: false,
    emitWorkspacePackageSummary: false,
  });
  const comparison = compareReports(previous, result.aggregated);
  const policyViolations = [
    ...result.policyViolations,
    ...evaluateComparePolicyViolations(previous, result.aggregated, opts.failOn),
  ];
  console.log("");
  console.log(formatCompareOutput(comparison));
  printPolicyViolations(policyViolations);
  printIncompleteEvidence(result.incompleteReasons);
  if (result.incompleteReasons.length > 0) {
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
  }
  if (policyViolations.length > 0) {
    process.exit(EXIT_POLICY_VIOLATION);
  }
}

/**
 * Run the CLI entrypoint and dispatch to the selected command.
 */
async function run(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.invalidCommand) {
    printHelp();
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
    return;
  }

  try {
    if ((opts.schema && !opts.commandProvided) || opts.command === "schema") {
      await runSchemaCommand(opts);
      return;
    }
    if (opts.command === "explain") {
      await runExplainCommand(opts);
      return;
    }
    if (opts.command === "why") {
      await runWhyCommand(opts);
      return;
    }
    if (opts.command === "compare") {
      await runCompareCommand(opts);
      return;
    }
    await runScanCommand(opts);
  } catch (err: any) {
    console.error("Failed to generate report:", err);
    process.exit(EXIT_USAGE_OR_INCOMPLETE);
  }
}

async function runSchemaCommand(opts: CliOptions): Promise<void> {
  const schema = renderReportJsonSchema();
  if (opts.outProvided) {
    const outputPath = path.resolve(opts.out);
    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.writeFile(outputPath, schema, "utf8");
    if (!opts.quiet) {
      console.log(statusLine("✔", `JSON schema written to ${outputPath}`));
    }
    return;
  }
  console.log(schema);
}

run();

function createProgressReporter(
  text: string,
  quiet: boolean,
): {
  stop: (success?: boolean) => void;
  update: (nextText: string) => void;
  log: (line: string) => void;
} {
  if (!quiet) return startSpinner(text);
  return {
    stop: () => {},
    update: () => {},
    log: (line: string) => {
      process.stdout.write(`${colorLeadingSymbol(line)}\n`);
    },
  };
}

/**
 * Displays a rotating CLI spinner with a message and returns controls to stop, update, or log lines.
 *
 * @param text - Initial message shown next to the spinner.
 * @returns An object with control methods:
 *  - `stop(success?)` - Stops the spinner and writes a final line using a check mark when `success` is `true` or a cross when `false` (defaults to `true`).
 *  - `update(nextText)` - Replaces the spinner's message with `nextText`.
 *  - `log(line)` - Writes `line` as a new output line above the active spinner without stopping it.
 */
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
