#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const path_1 = __importDefault(require("path"));
const child_process_1 = require("child_process");
const os_1 = require("os");
const aggregator_1 = require("./aggregator");
const importGraphRunner_1 = require("./runners/importGraphRunner");
const npmAudit_1 = require("./runners/npmAudit");
const npmLs_1 = require("./runners/npmLs");
const npmOutdated_1 = require("./runners/npmOutdated");
const report_1 = require("./report");
const promises_1 = __importDefault(require("fs/promises"));
const utils_1 = require("./utils");
function normalizeSlashes(p) {
    return p.split(path_1.default.sep).join("/");
}
function isCI() {
    return Boolean(process.env.CI === "true" ||
        process.env.CI === "TRUE" ||
        process.env.CI === "1" ||
        process.env.GITHUB_ACTIONS ||
        process.env.GITLAB_CI ||
        process.env.CIRCLECI ||
        process.env.JENKINS_URL ||
        process.env.BUILDKITE);
}
async function listDirs(parent) {
    const entries = await promises_1.default
        .readdir(parent, { withFileTypes: true })
        .catch(() => []);
    return entries
        .filter((e) => { var _a; return (_a = e === null || e === void 0 ? void 0 : e.isDirectory) === null || _a === void 0 ? void 0 : _a.call(e); })
        .map((e) => path_1.default.join(parent, e.name));
}
async function expandWorkspacePattern(root, pattern) {
    // Minimal glob support for common workspaces:
    // - "packages/*", "apps/*"
    // - "packages/**" (recursive)
    // - "./packages/*" (leading ./)
    const cleaned = pattern.trim().replace(/^[.][/\\]/, "");
    if (!cleaned)
        return [];
    // Disallow node_modules and hidden by default
    const parts = cleaned.split(/[/\\]/g).filter(Boolean);
    const isRecursive = parts.includes("**");
    // Find the segment containing * or **
    const starIndex = parts.findIndex((p) => p === "*" || p === "**");
    if (starIndex === -1) {
        const abs = path_1.default.resolve(root, cleaned);
        return (await (0, utils_1.pathExists)(abs)) ? [abs] : [];
    }
    const baseParts = parts.slice(0, starIndex);
    const baseDir = path_1.default.resolve(root, baseParts.join(path_1.default.sep));
    if (!(await (0, utils_1.pathExists)(baseDir)))
        return [];
    if (parts[starIndex] === "*" && starIndex === parts.length - 1) {
        // one-level children
        return await listDirs(baseDir);
    }
    if (parts[starIndex] === "**") {
        // recursive directories under base
        const out = [];
        async function walk(dir) {
            const children = await listDirs(dir);
            for (const child of children) {
                if (path_1.default.basename(child) === "node_modules")
                    continue;
                if (path_1.default.basename(child).startsWith("."))
                    continue;
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
async function readJsonFile(filePath) {
    try {
        const raw = await promises_1.default.readFile(filePath, "utf8");
        return JSON.parse(raw);
    }
    catch {
        return undefined;
    }
}
function stripYamlInlineComment(rawLine) {
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
function unquoteYamlScalar(value) {
    const trimmed = value.trim();
    if ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
        (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
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
function parseYamlScalar(value) {
    const normalized = value.trim();
    if (!normalized)
        return "";
    if (normalized === "{}")
        return {};
    if (normalized === "[]")
        return [];
    if (normalized === "null" || normalized === "~")
        return null;
    if (normalized === "true")
        return true;
    if (normalized === "false")
        return false;
    return unquoteYamlScalar(normalized);
}
function findYamlMapSeparator(content) {
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
        if (ch !== ":" || inSingle || inDouble)
            continue;
        const next = content[i + 1];
        if (next === undefined || next === " " || next === "\t") {
            return i;
        }
    }
    return -1;
}
function toObjectRecord(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return undefined;
    }
    return value;
}
function mergeRecordObjects(...objects) {
    const merged = {};
    for (const obj of objects) {
        if (!obj)
            continue;
        for (const [key, val] of Object.entries(obj)) {
            merged[key] = val;
        }
    }
    return Object.keys(merged).length > 0 ? merged : undefined;
}
function normalizeStringArray(value) {
    if (typeof value === "string") {
        const single = value.trim();
        return single ? [single] : [];
    }
    if (!Array.isArray(value))
        return [];
    return value
        .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
        .filter(Boolean);
}
function parseSimpleYaml(yaml) {
    var _a, _b;
    const lines = [];
    for (const rawLine of yaml.split(/\r?\n/)) {
        const noComment = stripYamlInlineComment(rawLine).replace(/\s+$/, "");
        if (!noComment.trim())
            continue;
        const indent = (_b = (_a = noComment.match(/^(\s*)/)) === null || _a === void 0 ? void 0 : _a[1].length) !== null && _b !== void 0 ? _b : 0;
        lines.push({
            indent,
            content: noComment.trim(),
        });
    }
    let index = 0;
    const parseNode = (indentLevel) => {
        if (index >= lines.length)
            return undefined;
        if (lines[index].indent < indentLevel)
            return undefined;
        if (lines[index].indent === indentLevel &&
            lines[index].content.startsWith("- ")) {
            return parseSequence(indentLevel);
        }
        return parseMapping(indentLevel);
    };
    const parseMapping = (indentLevel) => {
        const out = {};
        while (index < lines.length) {
            const line = lines[index];
            if (line.indent < indentLevel)
                break;
            if (line.indent > indentLevel) {
                index += 1;
                continue;
            }
            if (line.content.startsWith("- "))
                break;
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
            }
            else {
                out[key] = null;
            }
        }
        return out;
    };
    const parseSequence = (indentLevel) => {
        const values = [];
        while (index < lines.length) {
            const line = lines[index];
            if (line.indent < indentLevel)
                break;
            if (line.indent !== indentLevel || !line.content.startsWith("- "))
                break;
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
            }
            else {
                values.push(null);
            }
        }
        return values;
    };
    const root = parseNode(0);
    return toObjectRecord(root) || {};
}
function parsePnpmWorkspacePackagesFallback(yaml) {
    const patterns = [];
    const lines = yaml.split(/\r?\n/);
    let inPackages = false;
    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed)
            continue;
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
            if (m && m[1])
                patterns.push(m[1].trim());
        }
    }
    return patterns;
}
function parsePnpmWorkspaceFile(yaml) {
    var _a;
    const parsed = parseSimpleYaml(yaml);
    const fromYaml = normalizeStringArray(parsed.packages);
    const fromFallback = fromYaml.length > 0
        ? fromYaml
        : parsePnpmWorkspacePackagesFallback(yaml);
    const topLevelOverrides = toObjectRecord(parsed.overrides);
    const pnpmOverrides = toObjectRecord((_a = toObjectRecord(parsed.pnpm)) === null || _a === void 0 ? void 0 : _a.overrides);
    const overrides = mergeRecordObjects(topLevelOverrides, pnpmOverrides);
    return {
        packages: fromFallback,
        ...(overrides ? { overrides } : {}),
    };
}
async function getToolVersion(tool, cwd) {
    try {
        const result = await (0, utils_1.runCommand)(tool, ["--version"], { cwd });
        const raw = (result.stdout || "").trim();
        if (!raw)
            return undefined;
        return raw.split(/\s+/)[0];
    }
    catch {
        return undefined;
    }
}
function compactToolVersions(versions) {
    const out = {};
    for (const [key, value] of Object.entries(versions)) {
        if (value)
            out[key] = value;
    }
    return Object.keys(out).length > 0 ? out : undefined;
}
async function detectYarnPnP(projectPath) {
    if ((await (0, utils_1.pathExists)(path_1.default.join(projectPath, ".pnp.cjs"))) ||
        (await (0, utils_1.pathExists)(path_1.default.join(projectPath, ".pnp.js")))) {
        return true;
    }
    const yarnrc = path_1.default.join(projectPath, ".yarnrc.yml");
    if (!(await (0, utils_1.pathExists)(yarnrc)))
        return false;
    const content = await promises_1.default.readFile(yarnrc, "utf8").catch(() => "");
    return /nodeLinker\s*:\s*pnp\b/.test(content);
}
async function detectWorkspace(projectPath) {
    const rootPkgPath = path_1.default.join(projectPath, "package.json");
    const rootPkg = await readJsonFile(rootPkgPath);
    const inferredManager = inferPackageManager(rootPkg);
    const hasYarnLock = await (0, utils_1.pathExists)(path_1.default.join(projectPath, "yarn.lock"));
    const hasYarnPnp = await detectYarnPnP(projectPath);
    const pnpmWorkspacePath = path_1.default.join(projectPath, "pnpm-workspace.yaml");
    const hasPnpmWorkspace = await (0, utils_1.pathExists)(pnpmWorkspacePath);
    let type = "none";
    let patterns = [];
    let pnpmWorkspaceOverrides;
    if (hasPnpmWorkspace) {
        type = "pnpm";
        const yaml = await promises_1.default.readFile(pnpmWorkspacePath, "utf8");
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
        if (Array.isArray(rootPkg.workspaces))
            patterns = rootPkg.workspaces;
        else if (Array.isArray(rootPkg.workspaces.packages))
            patterns = rootPkg.workspaces.packages;
    }
    if (type === "none") {
        return { type: "none", packagePaths: [projectPath] };
    }
    // Expand patterns and keep only folders that contain package.json
    const candidates = [];
    for (const pat of patterns) {
        const expanded = await expandWorkspacePattern(projectPath, pat);
        candidates.push(...expanded);
    }
    const unique = Array.from(new Set(candidates.map((p) => path_1.default.resolve(p)))).filter((p) => !normalizeSlashes(p).includes("/node_modules/"));
    const packagePaths = [];
    for (const dir of unique) {
        const pkgJson = path_1.default.join(dir, "package.json");
        if (await (0, utils_1.pathExists)(pkgJson))
            packagePaths.push(dir);
    }
    // Always include root if it contains a name (some repos keep a root package)
    if (await (0, utils_1.pathExists)(path_1.default.join(projectPath, "package.json"))) {
        // root may already be in the list; keep unique
        if (!packagePaths.includes(projectPath)) {
            // Only include root as a scanned package if it looks like a real package
            const root = await readJsonFile(path_1.default.join(projectPath, "package.json"));
            if (root &&
                typeof root.name === "string" &&
                root.name.trim().length > 0) {
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
function inferPackageManager(rootPkg) {
    const raw = typeof (rootPkg === null || rootPkg === void 0 ? void 0 : rootPkg.packageManager) === "string"
        ? rootPkg.packageManager.trim()
        : "";
    if (!raw)
        return undefined;
    if (raw.startsWith("pnpm@") || raw === "pnpm")
        return "pnpm";
    if (raw.startsWith("yarn@") || raw === "yarn")
        return "yarn";
    if (raw.startsWith("npm@") || raw === "npm")
        return "npm";
    return undefined;
}
async function detectPackageManager(projectPath, rootPkg, workspaceType) {
    const inferred = inferPackageManager(rootPkg);
    if (inferred)
        return inferred;
    if (workspaceType === "pnpm" || workspaceType === "yarn")
        return workspaceType;
    if (await detectYarnPnP(projectPath))
        return "yarn";
    if (await (0, utils_1.pathExists)(path_1.default.join(projectPath, "node_modules", ".pnpm")))
        return "pnpm";
    if (await (0, utils_1.pathExists)(path_1.default.join(projectPath, "node_modules", ".yarn-state.yml")))
        return "yarn";
    return "npm";
}
async function detectScanManager(projectPath, fallback) {
    if (await (0, utils_1.pathExists)(path_1.default.join(projectPath, "pnpm-lock.yaml")))
        return "pnpm";
    if (await (0, utils_1.pathExists)(path_1.default.join(projectPath, "yarn.lock")))
        return "yarn";
    if ((await (0, utils_1.pathExists)(path_1.default.join(projectPath, "package-lock.json"))) ||
        (await (0, utils_1.pathExists)(path_1.default.join(projectPath, "npm-shrinkwrap.json")))) {
        return "npm";
    }
    if (await (0, utils_1.pathExists)(path_1.default.join(projectPath, "node_modules", ".pnpm")))
        return "pnpm";
    if (await (0, utils_1.pathExists)(path_1.default.join(projectPath, "node_modules", ".yarn-state.yml")))
        return "yarn";
    return fallback;
}
async function readWorkspacePackageMeta(rootPath, packagePaths) {
    const out = [];
    for (const p of packagePaths) {
        const pkg = await readJsonFile(path_1.default.join(p, "package.json"));
        const name = pkg && typeof pkg.name === "string" && pkg.name.trim()
            ? pkg.name.trim()
            : path_1.default.basename(p);
        out.push({ path: p, name, pkg: pkg || {} });
    }
    return out;
}
function isWorkspaceLocalSpecifier(value) {
    if (typeof value !== "string")
        return false;
    const trimmed = value.trim().toLowerCase();
    return (trimmed.startsWith("workspace:") ||
        trimmed.startsWith("link:") ||
        trimmed.startsWith("file:"));
}
function normalizeRelativePath(rootPath, packagePath) {
    const relative = path_1.default.relative(rootPath, packagePath);
    const normalized = relative.split(path_1.default.sep).join("/");
    return normalized && normalized.length > 0 ? normalized : ".";
}
function readDependencyEntries(source) {
    if (!source || typeof source !== "object")
        return [];
    const entries = [];
    for (const [name, spec] of Object.entries(source)) {
        if (typeof name !== "string" || !name.trim())
            continue;
        if (typeof spec !== "string" || !spec.trim())
            continue;
        entries.push([name, spec.trim()]);
    }
    return entries;
}
function isWorkspaceLocalDependency(dependencyName, spec, workspacePackageNames) {
    return workspacePackageNames.has(dependencyName) || isWorkspaceLocalSpecifier(spec);
}
function buildWorkspaceClassification(rootPath, packageMetas) {
    var _a, _b, _c, _d, _e;
    const workspacePackageNames = new Set(packageMetas.map((meta) => meta.name));
    const workspacePackageIds = new Set();
    const workspacePackagePaths = new Set();
    const localDependencyNames = new Set();
    const workspacePackages = [];
    for (const meta of packageMetas) {
        const version = typeof ((_a = meta.pkg) === null || _a === void 0 ? void 0 : _a.version) === "string" && meta.pkg.version.trim().length > 0
            ? meta.pkg.version.trim()
            : "workspace";
        workspacePackageIds.add(`${meta.name}@${version}`);
        workspacePackagePaths.add(path_1.default.resolve(meta.path));
        const runtimeExternal = new Set();
        const devExternal = new Set();
        const runtimeEntries = [
            ...readDependencyEntries((_b = meta.pkg) === null || _b === void 0 ? void 0 : _b.dependencies),
            ...readDependencyEntries((_c = meta.pkg) === null || _c === void 0 ? void 0 : _c.optionalDependencies),
        ];
        const devEntries = readDependencyEntries((_d = meta.pkg) === null || _d === void 0 ? void 0 : _d.devDependencies);
        const peerEntries = readDependencyEntries((_e = meta.pkg) === null || _e === void 0 ? void 0 : _e.peerDependencies);
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
        if (pathCompare !== 0)
            return pathCompare;
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
function mergeDepsFromWorkspace(pkgs, workspacePackageNames, localDependencyNames) {
    var _a, _b, _c, _d;
    const merged = {
        dependencies: {},
        devDependencies: {},
        optionalDependencies: {},
        peerDependencies: {},
    };
    const mergeSection = (target, source) => {
        for (const [depName, spec] of readDependencyEntries(source)) {
            if (isWorkspaceLocalDependency(depName, spec, workspacePackageNames)) {
                localDependencyNames.add(depName);
                continue;
            }
            target[depName] = spec;
        }
    };
    for (const entry of pkgs) {
        mergeSection(merged.dependencies, (_a = entry.pkg) === null || _a === void 0 ? void 0 : _a.dependencies);
        mergeSection(merged.devDependencies, (_b = entry.pkg) === null || _b === void 0 ? void 0 : _b.devDependencies);
        mergeSection(merged.optionalDependencies, (_c = entry.pkg) === null || _c === void 0 ? void 0 : _c.optionalDependencies);
        mergeSection(merged.peerDependencies, (_d = entry.pkg) === null || _d === void 0 ? void 0 : _d.peerDependencies);
    }
    return merged;
}
function mergeAuditResults(results) {
    const defined = results.filter(Boolean);
    if (defined.length === 0)
        return undefined;
    const base = {};
    for (const r of defined) {
        if (!r || typeof r !== "object")
            continue;
        // npm audit v7+ shape: { vulnerabilities: {..} }
        if (r.vulnerabilities && typeof r.vulnerabilities === "object") {
            base.vulnerabilities = base.vulnerabilities || {};
            for (const [k, v] of Object.entries(r.vulnerabilities)) {
                if (!base.vulnerabilities[k])
                    base.vulnerabilities[k] = v;
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
        if (r.metadata && !base.metadata)
            base.metadata = r.metadata;
    }
    return base;
}
function parseOutdatedData(data, unknownNames) {
    const entries = [];
    if (!data || typeof data !== "object")
        return entries;
    if (Array.isArray(data)) {
        for (const entry of data) {
            if (!entry || typeof entry !== "object")
                continue;
            const name = typeof entry.name === "string" ? entry.name : undefined;
            const current = typeof entry.current === "string" ? entry.current : "";
            const latest = typeof entry.latest === "string" ? entry.latest : undefined;
            const type = typeof entry.type === "string" ? entry.type.toLowerCase() : "";
            if (!name || !current)
                continue;
            let status = "unknown";
            if (type === "patch" || type === "minor" || type === "major") {
                status = type;
            }
            else if (latest) {
                status = classifyOutdated(current, latest);
            }
            if (status === "current")
                continue;
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
    for (const [name, info] of Object.entries(data)) {
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
        let status = "unknown";
        if (type === "patch" || type === "minor" || type === "major") {
            status = type;
        }
        else if (latest) {
            status = classifyOutdated(current, latest);
        }
        if (status === "current")
            continue;
        if (status === "major" || status === "minor" || status === "patch") {
            if (latest) {
                entries.push({
                    name,
                    currentVersion: current,
                    status,
                    latestVersion: latest,
                });
            }
            else {
                entries.push({ name, currentVersion: current, status: "unknown" });
            }
            continue;
        }
        entries.push({ name, currentVersion: current, status: "unknown" });
    }
    return entries;
}
function parseSimpleVersion(value) {
    if (!value || typeof value !== "string")
        return undefined;
    const trimmed = value.trim();
    if (!trimmed)
        return undefined;
    if (trimmed.includes("-") || trimmed.includes("+"))
        return undefined;
    const match = trimmed.match(/^v?(\d+)\.(\d+)\.(\d+)$/);
    if (!match)
        return undefined;
    const major = Number.parseInt(match[1], 10);
    const minor = Number.parseInt(match[2], 10);
    const patch = Number.parseInt(match[3], 10);
    if ([major, minor, patch].some((n) => Number.isNaN(n)))
        return undefined;
    return { major, minor, patch };
}
function classifyOutdated(current, latest) {
    const currentVer = parseSimpleVersion(current);
    const latestVer = parseSimpleVersion(latest);
    if (!currentVer || !latestVer)
        return "unknown";
    if (currentVer.major !== latestVer.major)
        return "major";
    if (currentVer.minor !== latestVer.minor)
        return "minor";
    if (currentVer.patch !== latestVer.patch)
        return "patch";
    return "current";
}
function mergeOutdatedResults(results) {
    const entries = [];
    const unknownNames = new Set();
    for (let i = 0; i < results.length; i++) {
        const attempt = results[i];
        if (!attempt.attempted)
            continue;
        const result = attempt.result;
        if (!result ||
            !result.ok ||
            !result.data ||
            typeof result.data !== "object") {
            continue;
        }
        entries.push(...parseOutdatedData(result.data, unknownNames));
    }
    if (entries.length === 0 && unknownNames.size === 0) {
        return undefined;
    }
    const merged = new Map();
    for (const entry of entries) {
        const key = `${entry.name}@${entry.currentVersion}`;
        const existing = merged.get(key);
        if (!existing) {
            merged.set(key, entry);
            continue;
        }
        if (existing.status !== entry.status ||
            existing.latestVersion !== entry.latestVersion) {
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
function mergeImportGraphs(rootPath, packageMetas, graphs) {
    const files = {};
    const packages = {};
    const packageCounts = {};
    const unresolvedImports = [];
    for (let i = 0; i < graphs.length; i++) {
        const g = graphs[i];
        const meta = packageMetas[i];
        if (!g || typeof g !== "object")
            continue;
        const relBase = path_1.default
            .relative(rootPath, meta.path)
            .split(path_1.default.sep)
            .join("/");
        const prefix = relBase ? `${relBase}/` : "";
        const gf = g.files || {};
        const gp = g.packages || {};
        const gc = g.packageCounts || {};
        for (const [k, v] of Object.entries(gf)) {
            files[`${prefix}${k}`] = Array.isArray(v)
                ? v.map((x) => `${prefix}${x}`)
                : [];
        }
        for (const [k, v] of Object.entries(gp)) {
            packages[`${prefix}${k}`] = Array.isArray(v) ? v : [];
        }
        for (const [k, v] of Object.entries(gc)) {
            if (!v || typeof v !== "object")
                continue;
            const next = {};
            for (const [dep, count] of Object.entries(v)) {
                if (typeof count === "number")
                    next[dep] = count;
            }
            packageCounts[`${prefix}${k}`] = next;
        }
        const unresolved = Array.isArray(g.unresolvedImports)
            ? g.unresolvedImports
            : [];
        unresolved.forEach((u) => {
            if (u &&
                typeof u.importer === "string" &&
                typeof u.specifier === "string") {
                unresolvedImports.push({
                    importer: `${prefix}${u.importer}`,
                    specifier: u.specifier,
                });
            }
        });
    }
    return { files, packages, packageCounts, unresolvedImports };
}
function buildWorkspaceUsageMap(packageMetas, dependencyGraphs, workspacePackageNames, localDependencyNames) {
    var _a, _b, _c, _d;
    const usage = new Map();
    const add = (depName, pkgName) => {
        if (!depName)
            return;
        if (workspacePackageNames.has(depName))
            return;
        if (localDependencyNames.has(depName))
            return;
        if (!usage.has(depName))
            usage.set(depName, new Set());
        usage.get(depName).add(pkgName);
    };
    // From declared deps
    for (const meta of packageMetas) {
        const pkgName = meta.name;
        const deps = ((_a = meta.pkg) === null || _a === void 0 ? void 0 : _a.dependencies) || {};
        const dev = ((_b = meta.pkg) === null || _b === void 0 ? void 0 : _b.devDependencies) || {};
        const opt = ((_c = meta.pkg) === null || _c === void 0 ? void 0 : _c.optionalDependencies) || {};
        const peer = ((_d = meta.pkg) === null || _d === void 0 ? void 0 : _d.peerDependencies) || {};
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
    const walk = (node, pkgName) => {
        if (!node || typeof node !== "object")
            return;
        const name = node.name;
        if (typeof name === "string")
            add(name, pkgName);
        const deps = node.dependencies;
        if (deps && typeof deps === "object") {
            for (const [depName, child] of Object.entries(deps)) {
                add(depName, pkgName);
                walk(child, pkgName);
            }
        }
    };
    for (let i = 0; i < dependencyGraphs.length; i++) {
        const data = dependencyGraphs[i];
        const meta = packageMetas[i];
        if (!data || typeof data !== "object")
            continue;
        const deps = data.dependencies;
        if (deps && typeof deps === "object") {
            for (const [depName, child] of Object.entries(deps)) {
                add(depName, meta.name);
                walk(child, meta.name);
            }
        }
    }
    const out = new Map();
    for (const [k, set] of usage.entries()) {
        out.set(k, Array.from(set).sort());
    }
    return out;
}
function buildCombinedDependencyGraph(rootPath, packageMetas, dependencyGraphs) {
    var _a;
    // Build a synthetic root with each workspace package as a top-level node.
    // This avoids object-key collisions for normal packages and preserves per-package roots.
    const dependencies = {};
    for (let i = 0; i < dependencyGraphs.length; i++) {
        const data = dependencyGraphs[i];
        const meta = packageMetas[i];
        if (!meta)
            continue;
        const version = typeof ((_a = meta.pkg) === null || _a === void 0 ? void 0 : _a.version) === "string" ? meta.pkg.version : "workspace";
        const nodeDeps = data &&
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
function parseArgs(argv) {
    const opts = {
        command: "scan",
        project: process.cwd(),
        out: "dependency-radar.html",
        keepTemp: false,
        audit: true,
        outdated: true,
        json: false,
        open: false,
    };
    const args = [...argv];
    if (args[0] && !args[0].startsWith("-")) {
        opts.command = args.shift();
    }
    while (args.length) {
        const arg = args.shift();
        if (!arg)
            break;
        if (arg === "--project" && args[0])
            opts.project = args.shift();
        else if (arg === "--out" && args[0])
            opts.out = args.shift();
        else if (arg === "--keep-temp")
            opts.keepTemp = true;
        else if (arg === "--offline") {
            opts.audit = false;
            opts.outdated = false;
        }
        else if (arg === "--json")
            opts.json = true;
        else if (arg === "--open")
            opts.open = true;
        else if (arg === "--help" || arg === "-h") {
            printHelp();
            process.exit(0);
        }
    }
    return opts;
}
function printHelp() {
    console.log(`dependency-radar [scan] [options]

If no command is provided, \`scan\` is run by default.

Options:
  --project <path>   Project folder (default: cwd)
  --out <path>       Output HTML file (default: dependency-radar.html)
  --json             Write aggregated data to JSON (default filename: dependency-radar.json)
  --keep-temp        Keep .dependency-radar folder
  --offline          Skip npm audit and npm outdated (useful for offline scans)
  --open             Open the generated report using the system default application
`);
}
function openInBrowser(filePath) {
    const normalizedPath = filePath.replace(/\\/g, "/");
    let child;
    switch ((0, os_1.platform)()) {
        case "darwin":
            child = (0, child_process_1.spawn)("open", [normalizedPath], {
                stdio: "ignore",
                shell: false,
                detached: true,
            });
            break;
        case "win32":
            child = (0, child_process_1.spawn)("cmd", ["/c", "start", "", normalizedPath], {
                stdio: "ignore",
                shell: false,
                detached: true,
            });
            break;
        default:
            child = (0, child_process_1.spawn)("xdg-open", [normalizedPath], {
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
/**
 * Orchestrates the CLI "scan" command to collect, merge, and output dependency data for a project or workspace.
 *
 * Detects workspace type and package manager, runs per-package collectors (audit, dependency tree, import graph, outdated),
 * merges collected signals into a workspace-level model, and writes a JSON or HTML report to the configured output path.
 * Manages a temporary working directory (created under the project as .dependency-radar), respects CLI options such as
 * JSON output, audit/outdated toggles, keeping the temp directory, and optionally opening the generated output with the
 * system default application. Exits the process with a non-zero code on fatal errors. */
async function run() {
    var _a;
    const opts = parseArgs(process.argv.slice(2));
    if (opts.command !== "scan") {
        printHelp();
        process.exit(1);
        return;
    }
    const projectPath = path_1.default.resolve(opts.project);
    if (opts.json && opts.out === "dependency-radar.html") {
        opts.out = "dependency-radar.json";
    }
    let outputPath = path_1.default.resolve(opts.out);
    const startTime = Date.now();
    let dependencyCount = 0;
    let outputCreated = false;
    try {
        const stat = await promises_1.default.stat(outputPath).catch(() => undefined);
        const endsWithSeparator = opts.out.endsWith("/") || opts.out.endsWith("\\");
        const hasExtension = Boolean(path_1.default.extname(outputPath));
        if ((stat && stat.isDirectory()) ||
            endsWithSeparator ||
            (!stat && !hasExtension)) {
            outputPath = path_1.default.join(outputPath, opts.json ? "dependency-radar.json" : "dependency-radar.html");
        }
    }
    catch (e) {
        // ignore, best-effort path normalization
    }
    const tempDir = path_1.default.join(projectPath, ".dependency-radar");
    // Stage 1: detect workspace/package-manager context and collect tool versions.
    const workspace = await detectWorkspace(projectPath);
    const yarnPnP = await detectYarnPnP(projectPath);
    if (workspace.type === "yarn" && workspace.packagePaths.length === 0) {
        console.error("Yarn Plug'n'Play (nodeLinker: pnp) detected. This is not supported yet.");
        console.error("Switch to nodeLinker: node-modules or run in a non-PnP environment.");
        process.exit(1);
        return;
    }
    const hasProjectNodeModules = await (0, utils_1.pathExists)(path_1.default.join(projectPath, "node_modules"));
    if (!hasProjectNodeModules) {
        const workspaceHint = workspace.type === "none"
            ? "single project"
            : `${workspace.type.toUpperCase()} workspace`;
        const yarnHint = yarnPnP
            ? " Yarn Plug'n'Play appears enabled; Dependency Radar currently requires node_modules linker."
            : "";
        console.warn(`⚠ node_modules was not found at ${projectPath}. Scan completeness may be reduced for this ${workspaceHint}. Run your package manager install (npm install, pnpm install, or yarn install) before scanning.${yarnHint}`);
    }
    const rootPkg = await readJsonFile(path_1.default.join(projectPath, "package.json"));
    const projectDependencyPolicy = workspace.pnpmWorkspaceOverrides
        ? {
            overrides: workspace.pnpmWorkspaceOverrides,
            sources: ["pnpm-workspace.yaml#overrides"],
        }
        : undefined;
    const packageManager = await detectPackageManager(projectPath, rootPkg, workspace.type);
    const scanManager = await detectScanManager(projectPath, packageManager);
    const packageManagerField = typeof (rootPkg === null || rootPkg === void 0 ? void 0 : rootPkg.packageManager) === "string"
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
    const packageManagerVersion = scanManager === "npm"
        ? npmVersion
        : scanManager === "pnpm"
            ? pnpmVersion
            : yarnVersion;
    if (packageManager === "yarn" && yarnPnP) {
        console.error("Yarn Plug'n'Play (nodeLinker: pnp) detected. This is not supported yet.");
        console.error("Switch to nodeLinker: node-modules or run in a non-PnP environment.");
        process.exit(1);
        return;
    }
    const packagePaths = workspace.packagePaths;
    const workspaceLabel = workspace.type === "none"
        ? "Single project"
        : `${workspace.type.toUpperCase()} workspace`;
    console.log(`✔ ${workspaceLabel} detected`);
    if (workspace.type !== "none" && scanManager !== workspace.type) {
        console.log(`✔ Using ${scanManager.toUpperCase()} for dependency data (lockfile detected)`);
    }
    const spinner = startSpinner(`Scanning ${workspaceLabel} at ${projectPath}`);
    try {
        await (0, utils_1.ensureDir)(tempDir);
        // Stage 2: run per-package collectors and persist raw tool outputs.
        const packageMetas = await readWorkspacePackageMeta(projectPath, packagePaths);
        const workspaceClassification = buildWorkspaceClassification(projectPath, packageMetas);
        const perPackageAudit = [];
        const perPackageLs = [];
        const perPackageImportGraph = [];
        const perPackageOutdated = [];
        for (const meta of packageMetas) {
            spinner.update(`Scanning ${workspaceLabel} (${perPackageLs.length + 1}/${packageMetas.length}) at ${projectPath}`);
            const pkgTempDir = path_1.default.join(tempDir, meta.name.replace(/[^a-zA-Z0-9._-]/g, "_"));
            await (0, utils_1.ensureDir)(pkgTempDir);
            const [a, l, ig, o] = await Promise.all([
                opts.audit
                    ? (0, npmAudit_1.runPackageAudit)(meta.path, pkgTempDir, scanManager, yarnVersion).catch((err) => ({ ok: false, error: String(err) }))
                    : Promise.resolve(undefined),
                (0, npmLs_1.runNpmLs)(meta.path, pkgTempDir, scanManager, {
                    contextLabel: meta.name,
                    lockfileSearchRoot: projectPath,
                    onProgress: (line) => spinner.log(line),
                }).catch((err) => ({ ok: false, error: String(err) })),
                (0, importGraphRunner_1.runImportGraph)(meta.path, pkgTempDir).catch((err) => ({ ok: false, error: String(err) })),
                opts.outdated
                    ? (0, npmOutdated_1.runPackageOutdated)(meta.path, pkgTempDir, scanManager).catch((err) => ({ ok: false, error: String(err) }))
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
                spinner.log(`✔ ${scanManager.toUpperCase()} audit data collected`);
            }
            else {
                spinner.log(`✖ ${scanManager.toUpperCase()} audit data unavailable`);
            }
        }
        if (opts.outdated) {
            const outdatedOk = perPackageOutdated.every((r) => r.result && r.result.ok);
            if (outdatedOk) {
                spinner.log(`✔ ${scanManager.toUpperCase()} outdated data collected`);
            }
            else {
                spinner.log(`✖ ${scanManager.toUpperCase()} outdated data unavailable`);
            }
        }
        const mergedAuditData = mergeAuditResults(perPackageAudit.map((r) => (r && r.ok ? r.data : undefined)));
        const mergedGraphData = workspace.type === "none"
            ? perPackageLs[0] && perPackageLs[0].ok
                ? perPackageLs[0].data
                : undefined
            : buildCombinedDependencyGraph(projectPath, packageMetas, perPackageLs.map((r) => (r && r.ok ? r.data : undefined)));
        const mergedImportGraphData = mergeImportGraphs(projectPath, packageMetas, perPackageImportGraph.map((r) => (r && r.ok ? r.data : undefined)));
        const workspaceUsage = buildWorkspaceUsageMap(packageMetas, perPackageLs.map((r) => (r && r.ok ? r.data : undefined)), workspaceClassification.workspacePackageNames, workspaceClassification.localDependencyNames);
        const outdatedResult = mergeOutdatedResults(perPackageOutdated);
        const auditResult = mergedAuditData
            ? { ok: true, data: mergedAuditData }
            : undefined;
        const npmLsResult = { ok: true, data: mergedGraphData };
        const importGraphResult = { ok: true, data: mergedImportGraphData };
        // Build a merged package.json view for aggregator direct-dep checks.
        const mergedPkgForAggregator = mergeDepsFromWorkspace(packageMetas, workspaceClassification.workspacePackageNames, workspaceClassification.localDependencyNames);
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
            const packageList = lsFailures.map((entry) => { var _a; return (_a = entry.meta) === null || _a === void 0 ? void 0 : _a.name; }).filter(Boolean);
            spinner.log(`Dependency tree warning: ${lsFailures.length} package${lsFailures.length === 1 ? "" : "s"} failed (${packageList.join(", ")}).`);
            spinner.log(`First dependency tree error: ${((_a = lsFailures[0].result) === null || _a === void 0 ? void 0 : _a.error) || "pnpm ls failed"}`);
        }
        if (importFailures.length > 0) {
            spinner.log(`Import graph warning: ${importFailures.length} package${importFailures.length === 1 ? "" : "s"} failed (${importFailures[0].error || "import graph failed"})`);
        }
        // Stage 4: aggregate all signals into the final report model.
        const aggregated = await (0, aggregator_1.aggregateData)({
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
                    workspaceLocalDependencyNames: workspaceClassification.localDependencyNames,
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
        if (workspace.type !== "none") {
            console.log(`Detected ${workspace.type.toUpperCase()} workspace with ${packagePaths.length} package${packagePaths.length === 1 ? "" : "s"}.`);
        }
        if (dependencyCount > 0) {
            if (opts.json) {
                await promises_1.default.mkdir(path_1.default.dirname(outputPath), { recursive: true });
                await promises_1.default.writeFile(outputPath, JSON.stringify(aggregated, null, 2), "utf8");
            }
            else {
                await (0, report_1.renderReport)(aggregated, outputPath);
            }
            outputCreated = true;
        }
        spinner.stop(true);
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        console.log(`✔ Scan complete: ${dependencyCount} dependencies analysed in ${elapsed}s`);
        if (outputCreated) {
            console.log(`✔ ${opts.json ? "JSON" : "Report"} written to ${outputPath}`);
        }
        else {
            console.log(`✖ No dependencies were found - ${opts.json ? "JSON file" : "Report"} not created`);
        }
    }
    catch (err) {
        spinner.stop(false);
        console.error("Failed to generate report:", err);
        process.exit(1);
    }
    finally {
        if (!opts.keepTemp) {
            await (0, utils_1.removeDir)(tempDir);
        }
        else {
            console.log(`✔ Temporary data kept at ${tempDir}`);
        }
    }
    if (opts.open && outputCreated && !isCI()) {
        console.log(`↗ Opening ${path_1.default.basename(outputPath)} using system default ${opts.json ? "application" : "browser"}.`);
        openInBrowser(outputPath);
    }
    else if (opts.open && outputCreated && isCI()) {
        console.log("✖ Skipping auto-open in CI environment.");
    }
    // Always show CTA as the last output
    console.log("");
    console.log("Get additional risk analysis and a management-ready summary at https://dependency-radar.com");
}
run();
function startSpinner(text) {
    const frames = ["|", "/", "-", "\\"];
    let i = 0;
    let currentText = text;
    const shortenPathInMessage = (message) => {
        const marker = ' at ';
        const idx = message.lastIndexOf(marker);
        if (idx === -1)
            return message;
        const head = message.slice(0, idx + marker.length);
        const rawPath = message.slice(idx + marker.length).trim();
        if (!rawPath)
            return message;
        const segments = rawPath.split(/[\\/]+/).filter(Boolean);
        if (segments.length === 0)
            return message;
        const tail = segments.slice(-2).join('/');
        return `${head}…/${tail}`;
    };
    const formatLine = (prefix, value) => {
        if (!process.stdout.isTTY)
            return `${prefix} ${value}`;
        const displayValue = shortenPathInMessage(value);
        const columns = process.stdout.columns || 0;
        if (columns <= 0)
            return `${prefix} ${displayValue}`;
        const max = columns - (prefix.length + 1);
        if (max <= 0)
            return prefix;
        if (displayValue.length <= max)
            return `${prefix} ${displayValue}`;
        const ellipsis = "…";
        const keep = Math.max(0, max - ellipsis.length);
        return `${prefix} ${displayValue.slice(0, keep)}${ellipsis}`;
    };
    process.stdout.write(formatLine(frames[i], currentText));
    const timer = setInterval(() => {
        i = (i + 1) % frames.length;
        process.stdout.write(`\r\x1b[K${formatLine(frames[i], currentText)}`);
    }, 120);
    let stopped = false;
    const stop = (success = true) => {
        if (stopped)
            return;
        stopped = true;
        clearInterval(timer);
        process.stdout.write(`\r\x1b[K${formatLine(success ? "✔" : "✖", currentText)}\n`);
    };
    const update = (nextText) => {
        if (stopped)
            return;
        currentText = nextText;
        process.stdout.write(`\r\x1b[K${formatLine(frames[i], currentText)}`);
    };
    const log = (line) => {
        if (stopped) {
            process.stdout.write(`${line}\n`);
            return;
        }
        process.stdout.write(`\r\x1b[K${line}\n`);
        process.stdout.write(formatLine(frames[i], currentText));
    };
    return { stop, update, log };
}
