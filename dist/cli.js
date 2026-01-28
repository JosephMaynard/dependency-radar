#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const path_1 = __importDefault(require("path"));
const aggregator_1 = require("./aggregator");
const importGraphRunner_1 = require("./runners/importGraphRunner");
const npmAudit_1 = require("./runners/npmAudit");
const npmLs_1 = require("./runners/npmLs");
const report_1 = require("./report");
const promises_1 = __importDefault(require("fs/promises"));
const utils_1 = require("./utils");
async function pathExists(target) {
    try {
        await promises_1.default.stat(target);
        return true;
    }
    catch {
        return false;
    }
}
function normalizeSlashes(p) {
    return p.split(path_1.default.sep).join('/');
}
async function listDirs(parent) {
    const entries = await promises_1.default.readdir(parent, { withFileTypes: true }).catch(() => []);
    return entries
        .filter((e) => { var _a; return (_a = e === null || e === void 0 ? void 0 : e.isDirectory) === null || _a === void 0 ? void 0 : _a.call(e); })
        .map((e) => path_1.default.join(parent, e.name));
}
async function expandWorkspacePattern(root, pattern) {
    // Minimal glob support for common workspaces:
    // - "packages/*", "apps/*"
    // - "packages/**" (recursive)
    // - "./packages/*" (leading ./)
    const cleaned = pattern.trim().replace(/^[.][/\\]/, '');
    if (!cleaned)
        return [];
    // Disallow node_modules and hidden by default
    const parts = cleaned.split(/[/\\]/g).filter(Boolean);
    const isRecursive = parts.includes('**');
    // Find the segment containing * or **
    const starIndex = parts.findIndex((p) => p === '*' || p === '**');
    if (starIndex === -1) {
        const abs = path_1.default.resolve(root, cleaned);
        return (await pathExists(abs)) ? [abs] : [];
    }
    const baseParts = parts.slice(0, starIndex);
    const baseDir = path_1.default.resolve(root, baseParts.join(path_1.default.sep));
    if (!(await pathExists(baseDir)))
        return [];
    if (parts[starIndex] === '*' && starIndex === parts.length - 1) {
        // one-level children
        return await listDirs(baseDir);
    }
    if (parts[starIndex] === '**') {
        // recursive directories under base
        const out = [];
        async function walk(dir) {
            const children = await listDirs(dir);
            for (const child of children) {
                if (path_1.default.basename(child) === 'node_modules')
                    continue;
                if (path_1.default.basename(child).startsWith('.'))
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
        const raw = await promises_1.default.readFile(filePath, 'utf8');
        return JSON.parse(raw);
    }
    catch {
        return undefined;
    }
}
async function detectWorkspace(projectPath) {
    const rootPkgPath = path_1.default.join(projectPath, 'package.json');
    const rootPkg = await readJsonFile(rootPkgPath);
    const pnpmWorkspacePath = path_1.default.join(projectPath, 'pnpm-workspace.yaml');
    const hasPnpmWorkspace = await pathExists(pnpmWorkspacePath);
    let type = 'none';
    let patterns = [];
    if (hasPnpmWorkspace) {
        type = 'pnpm';
        // very small YAML parser for the only thing we care about: `packages:` list.
        const yaml = await promises_1.default.readFile(pnpmWorkspacePath, 'utf8');
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
                // stop when we hit a new top-level key
                if (/^[A-Za-z0-9_-]+\s*:/.test(trimmed) && !trimmed.startsWith('-')) {
                    inPackages = false;
                    continue;
                }
                const m = trimmed.match(/^[-]\s*["']?([^"']+)["']?\s*$/);
                if (m && m[1])
                    patterns.push(m[1].trim());
            }
        }
    }
    // npm/yarn workspaces
    if (type === 'none' && rootPkg && rootPkg.workspaces) {
        type = 'npm';
        if (Array.isArray(rootPkg.workspaces))
            patterns = rootPkg.workspaces;
        else if (Array.isArray(rootPkg.workspaces.packages))
            patterns = rootPkg.workspaces.packages;
        // try to detect yarn berry pnp (unsupported) later via .yarnrc.yml
        const yarnrc = path_1.default.join(projectPath, '.yarnrc.yml');
        if (await pathExists(yarnrc)) {
            const y = await promises_1.default.readFile(yarnrc, 'utf8');
            if (/nodeLinker\s*:\s*pnp/.test(y)) {
                return { type: 'yarn', packagePaths: [] };
            }
        }
    }
    if (type === 'none') {
        return { type: 'none', packagePaths: [projectPath] };
    }
    // Expand patterns and keep only folders that contain package.json
    const candidates = [];
    for (const pat of patterns) {
        const expanded = await expandWorkspacePattern(projectPath, pat);
        candidates.push(...expanded);
    }
    const unique = Array.from(new Set(candidates.map((p) => path_1.default.resolve(p))))
        .filter((p) => !normalizeSlashes(p).includes('/node_modules/'));
    const packagePaths = [];
    for (const dir of unique) {
        const pkgJson = path_1.default.join(dir, 'package.json');
        if (await pathExists(pkgJson))
            packagePaths.push(dir);
    }
    // Always include root if it contains a name (some repos keep a root package)
    if (await pathExists(path_1.default.join(projectPath, 'package.json'))) {
        // root may already be in the list; keep unique
        if (!packagePaths.includes(projectPath)) {
            // Only include root as a scanned package if it looks like a real package
            const root = await readJsonFile(path_1.default.join(projectPath, 'package.json'));
            if (root && typeof root.name === 'string' && root.name.trim().length > 0) {
                packagePaths.push(projectPath);
            }
        }
    }
    return { type, packagePaths: packagePaths.sort() };
}
async function readWorkspacePackageMeta(rootPath, packagePaths) {
    const out = [];
    for (const p of packagePaths) {
        const pkg = await readJsonFile(path_1.default.join(p, 'package.json'));
        const name = (pkg && typeof pkg.name === 'string' && pkg.name.trim()) ? pkg.name.trim() : path_1.default.basename(p);
        out.push({ path: p, name, pkg: pkg || {} });
    }
    return out;
}
function mergeDepsFromWorkspace(pkgs) {
    var _a, _b;
    const merged = { dependencies: {}, devDependencies: {} };
    for (const entry of pkgs) {
        const deps = ((_a = entry.pkg) === null || _a === void 0 ? void 0 : _a.dependencies) || {};
        const dev = ((_b = entry.pkg) === null || _b === void 0 ? void 0 : _b.devDependencies) || {};
        Object.assign(merged.dependencies, deps);
        Object.assign(merged.devDependencies, dev);
    }
    return merged;
}
function mergeAuditResults(results) {
    const defined = results.filter(Boolean);
    if (defined.length === 0)
        return undefined;
    const base = {};
    for (const r of defined) {
        if (!r || typeof r !== 'object')
            continue;
        // npm audit v7+ shape: { vulnerabilities: {..} }
        if (r.vulnerabilities && typeof r.vulnerabilities === 'object') {
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
        if (r.advisories && typeof r.advisories === 'object') {
            base.advisories = base.advisories || {};
            Object.assign(base.advisories, r.advisories);
        }
        // keep metadata if present
        if (r.metadata && !base.metadata)
            base.metadata = r.metadata;
    }
    return base;
}
function mergeImportGraphs(rootPath, packageMetas, graphs) {
    const files = {};
    const packages = {};
    const packageCounts = {};
    const unresolvedImports = [];
    for (let i = 0; i < graphs.length; i++) {
        const g = graphs[i];
        const meta = packageMetas[i];
        if (!g || typeof g !== 'object')
            continue;
        const relBase = path_1.default.relative(rootPath, meta.path).split(path_1.default.sep).join('/');
        const prefix = relBase ? `${relBase}/` : '';
        const gf = g.files || {};
        const gp = g.packages || {};
        const gc = g.packageCounts || {};
        for (const [k, v] of Object.entries(gf)) {
            files[`${prefix}${k}`] = Array.isArray(v) ? v.map((x) => `${prefix}${x}`) : [];
        }
        for (const [k, v] of Object.entries(gp)) {
            packages[`${prefix}${k}`] = Array.isArray(v) ? v : [];
        }
        for (const [k, v] of Object.entries(gc)) {
            if (!v || typeof v !== 'object')
                continue;
            const next = {};
            for (const [dep, count] of Object.entries(v)) {
                if (typeof count === 'number')
                    next[dep] = count;
            }
            packageCounts[`${prefix}${k}`] = next;
        }
        const unresolved = Array.isArray(g.unresolvedImports) ? g.unresolvedImports : [];
        unresolved.forEach((u) => {
            if (u && typeof u.importer === 'string' && typeof u.specifier === 'string') {
                unresolvedImports.push({ importer: `${prefix}${u.importer}`, specifier: u.specifier });
            }
        });
    }
    return { files, packages, packageCounts, unresolvedImports };
}
function buildWorkspaceUsageMap(packageMetas, npmLsDatas) {
    var _a, _b;
    const usage = new Map();
    const add = (depName, pkgName) => {
        if (!depName)
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
        Object.keys(deps).forEach((d) => add(d, pkgName));
        Object.keys(dev).forEach((d) => add(d, pkgName));
    }
    // From npm ls trees (transitives)
    const walk = (node, pkgName) => {
        if (!node || typeof node !== 'object')
            return;
        const name = node.name;
        if (typeof name === 'string')
            add(name, pkgName);
        const deps = node.dependencies;
        if (deps && typeof deps === 'object') {
            for (const [depName, child] of Object.entries(deps)) {
                add(depName, pkgName);
                walk(child, pkgName);
            }
        }
    };
    for (let i = 0; i < npmLsDatas.length; i++) {
        const data = npmLsDatas[i];
        const meta = packageMetas[i];
        if (!data || typeof data !== 'object')
            continue;
        const deps = data.dependencies;
        if (deps && typeof deps === 'object') {
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
function buildCombinedNpmLs(rootPath, packageMetas, npmLsDatas) {
    var _a;
    // Build a synthetic root with each workspace package as a top-level node.
    // This avoids object-key collisions for normal packages and preserves per-package roots.
    const dependencies = {};
    for (let i = 0; i < npmLsDatas.length; i++) {
        const data = npmLsDatas[i];
        const meta = packageMetas[i];
        if (!meta)
            continue;
        const version = typeof ((_a = meta.pkg) === null || _a === void 0 ? void 0 : _a.version) === 'string' ? meta.pkg.version : 'workspace';
        const nodeDeps = (data && typeof data === 'object' && data.dependencies && typeof data.dependencies === 'object')
            ? data.dependencies
            : {};
        dependencies[meta.name] = {
            name: meta.name,
            version,
            dependencies: nodeDeps
        };
    }
    return { name: 'dependency-radar-workspace', version: '0.0.0', dependencies };
}
function parseArgs(argv) {
    const opts = {
        command: 'scan',
        project: process.cwd(),
        out: 'dependency-radar.html',
        keepTemp: false,
        audit: true,
        json: false
    };
    const args = [...argv];
    if (args[0] && !args[0].startsWith('-')) {
        opts.command = args.shift();
    }
    while (args.length) {
        const arg = args.shift();
        if (!arg)
            break;
        if (arg === '--project' && args[0])
            opts.project = args.shift();
        else if (arg === '--out' && args[0])
            opts.out = args.shift();
        else if (arg === '--keep-temp')
            opts.keepTemp = true;
        else if (arg === '--no-audit')
            opts.audit = false;
        else if (arg === '--json')
            opts.json = true;
        else if (arg === '--help' || arg === '-h') {
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
  --no-audit         Skip npm audit (useful for offline scans)
`);
}
async function run() {
    const opts = parseArgs(process.argv.slice(2));
    if (opts.command !== 'scan') {
        printHelp();
        process.exit(1);
        return;
    }
    const projectPath = path_1.default.resolve(opts.project);
    if (opts.json && opts.out === 'dependency-radar.html') {
        opts.out = 'dependency-radar.json';
    }
    let outputPath = path_1.default.resolve(opts.out);
    const startTime = Date.now();
    let dependencyCount = 0;
    try {
        const stat = await promises_1.default.stat(outputPath).catch(() => undefined);
        const endsWithSeparator = opts.out.endsWith('/') || opts.out.endsWith('\\');
        const hasExtension = Boolean(path_1.default.extname(outputPath));
        if ((stat && stat.isDirectory()) || endsWithSeparator || (!stat && !hasExtension)) {
            outputPath = path_1.default.join(outputPath, opts.json ? 'dependency-radar.json' : 'dependency-radar.html');
        }
    }
    catch (e) {
        // ignore, best-effort path normalization
    }
    const tempDir = path_1.default.join(projectPath, '.dependency-radar');
    // Workspace detection and reporting
    const workspace = await detectWorkspace(projectPath);
    if (workspace.type === 'yarn' && workspace.packagePaths.length === 0) {
        console.error('Yarn Plug\'n\'Play (nodeLinker: pnp) detected. This is not supported yet.');
        console.error('Switch to nodeLinker: node-modules or run in a non-PnP environment.');
        process.exit(1);
        return;
    }
    const packagePaths = workspace.packagePaths;
    const workspaceLabel = workspace.type === 'none' ? 'Single project' : `${workspace.type.toUpperCase()} workspace`;
    const stopSpinner = startSpinner(`Scanning ${workspaceLabel} at ${projectPath}`);
    try {
        await (0, utils_1.ensureDir)(tempDir);
        // Run tools per package for best coverage.
        const packageMetas = await readWorkspacePackageMeta(projectPath, packagePaths);
        const perPackageAudit = [];
        const perPackageLs = [];
        const perPackageImportGraph = [];
        for (const meta of packageMetas) {
            const pkgTempDir = path_1.default.join(tempDir, meta.name.replace(/[^a-zA-Z0-9._-]/g, '_'));
            await (0, utils_1.ensureDir)(pkgTempDir);
            const [a, l, ig] = await Promise.all([
                opts.audit ? (0, npmAudit_1.runNpmAudit)(meta.path, pkgTempDir).catch((err) => ({ ok: false, error: String(err) })) : Promise.resolve(undefined),
                (0, npmLs_1.runNpmLs)(meta.path, pkgTempDir).catch((err) => ({ ok: false, error: String(err) })),
                (0, importGraphRunner_1.runImportGraph)(meta.path, pkgTempDir).catch((err) => ({ ok: false, error: String(err) }))
            ]);
            perPackageAudit.push(a);
            perPackageLs.push(l);
            perPackageImportGraph.push(ig);
        }
        const mergedAuditData = mergeAuditResults(perPackageAudit.map((r) => (r && r.ok ? r.data : undefined)));
        const mergedLsData = buildCombinedNpmLs(projectPath, packageMetas, perPackageLs.map((r) => (r && r.ok ? r.data : undefined)));
        const mergedImportGraphData = mergeImportGraphs(projectPath, packageMetas, perPackageImportGraph.map((r) => (r && r.ok ? r.data : undefined)));
        const workspaceUsage = buildWorkspaceUsageMap(packageMetas, perPackageLs.map((r) => (r && r.ok ? r.data : undefined)));
        const auditResult = mergedAuditData ? { ok: true, data: mergedAuditData } : undefined;
        const npmLsResult = { ok: true, data: mergedLsData };
        const importGraphResult = { ok: true, data: mergedImportGraphData };
        // Build a merged package.json view for aggregator direct-dep checks.
        const mergedPkgForAggregator = mergeDepsFromWorkspace(packageMetas);
        const auditFailure = opts.audit ? perPackageAudit.find((r) => r && !r.ok) : undefined;
        const lsFailure = perPackageLs.find((r) => r && !r.ok);
        const importFailure = perPackageImportGraph.find((r) => r && !r.ok);
        if (auditFailure || lsFailure || importFailure) {
            const err = auditFailure || lsFailure || importFailure;
            throw new Error((err === null || err === void 0 ? void 0 : err.error) || 'Tool execution failed');
        }
        const aggregated = await (0, aggregator_1.aggregateData)({
            projectPath,
            auditResult,
            npmLsResult,
            importGraphResult,
            pkgOverride: mergedPkgForAggregator,
            workspaceUsage,
            workspaceEnabled: workspace.type !== 'none',
        });
        dependencyCount = Object.keys(aggregated.dependencies).length;
        if (workspace.type !== 'none') {
            console.log(`Detected ${workspace.type.toUpperCase()} workspace with ${packagePaths.length} package${packagePaths.length === 1 ? '' : 's'}.`);
        }
        if (opts.json) {
            await promises_1.default.mkdir(path_1.default.dirname(outputPath), { recursive: true });
            await promises_1.default.writeFile(outputPath, JSON.stringify(aggregated, null, 2), 'utf8');
        }
        else {
            await (0, report_1.renderReport)(aggregated, outputPath);
        }
        stopSpinner(true);
        console.log(`${opts.json ? 'JSON' : 'Report'} written to ${outputPath}`);
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        console.log(`Scan complete: ${dependencyCount} dependencies analysed in ${elapsed}s`);
    }
    catch (err) {
        stopSpinner(false);
        console.error('Failed to generate report:', err);
        process.exit(1);
    }
    finally {
        if (!opts.keepTemp) {
            await (0, utils_1.removeDir)(tempDir);
        }
        else {
            console.log(`Temporary data kept at ${tempDir}`);
        }
    }
    // Always show CTA as the last output
    console.log('');
    console.log('Get additional risk analysis and a management-ready summary at https://dependency-radar.com');
}
run();
function startSpinner(text) {
    const frames = ['|', '/', '-', '\\'];
    let i = 0;
    process.stdout.write(`${frames[i]} ${text}`);
    const timer = setInterval(() => {
        i = (i + 1) % frames.length;
        process.stdout.write(`\r${frames[i]} ${text}`);
    }, 120);
    let stopped = false;
    return (success = true) => {
        if (stopped)
            return;
        stopped = true;
        clearInterval(timer);
        process.stdout.write(`\r${success ? '✔' : '✖'} ${text}\n`);
    };
}
