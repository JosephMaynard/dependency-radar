"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runPackageOutdated = runPackageOutdated;
const path_1 = __importDefault(require("path"));
const utils_1 = require("../utils");
function normalizeOutdatedOutput(tool, data) {
    if (!data)
        return undefined;
    if (typeof data === "object" && !Array.isArray(data) && !data.type)
        return data;
    // Yarn JSONL table output (classic) must be checked before generic array parsing.
    const entries = Array.isArray(data) ? data : [data];
    const tableEntry = entries.find((e) => { var _a; return e && typeof e === "object" && (e.type === "table" || ((_a = e.data) === null || _a === void 0 ? void 0 : _a.body)); });
    const table = (tableEntry === null || tableEntry === void 0 ? void 0 : tableEntry.data) || tableEntry;
    if (table && Array.isArray(table.head) && Array.isArray(table.body)) {
        const head = table.head.map((h) => String(h).toLowerCase());
        const idx = {
            name: head.findIndex((h) => h.includes("package") || h.includes("name")),
            current: head.findIndex((h) => h.includes("current")),
            latest: head.findIndex((h) => h.includes("latest")),
            wanted: head.findIndex((h) => h.includes("wanted")),
        };
        const out = {};
        for (const row of table.body) {
            if (!Array.isArray(row))
                continue;
            const name = idx.name >= 0 ? String(row[idx.name]) : "";
            if (!name)
                continue;
            out[name] = {
                current: idx.current >= 0 ? String(row[idx.current]) : undefined,
                latest: idx.latest >= 0 ? String(row[idx.latest]) : undefined,
                wanted: idx.wanted >= 0 ? String(row[idx.wanted]) : undefined,
            };
        }
        return Object.keys(out).length > 0 ? out : undefined;
    }
    if (Array.isArray(data)) {
        // pnpm often returns arrays of rows
        const out = {};
        for (const entry of data) {
            if (!entry || typeof entry !== "object")
                continue;
            const name = entry.name || entry.packageName;
            if (typeof name !== "string" || !name.trim())
                continue;
            out[name] = {
                current: entry.current || entry.currentVersion || entry.from,
                latest: entry.latest || entry.latestVersion || entry.to,
                wanted: entry.wanted,
            };
        }
        return Object.keys(out).length > 0 ? out : undefined;
    }
    if (tool === "pnpm" && data.outdated)
        return data.outdated;
    return undefined;
}
function isYarnOutdatedUnsupported(result) {
    const output = `${result.stdout}\n${result.stderr}`;
    return /Couldn't find a script named "outdated"/i.test(output);
}
function buildOutdatedCommand(tool) {
    if (tool === "pnpm") {
        return {
            cmd: "pnpm",
            args: ["outdated", "--json"],
            lockFiles: ["pnpm-lock.yaml"],
        };
    }
    if (tool === "yarn") {
        return {
            cmd: "yarn",
            args: ["outdated", "--json"],
            lockFiles: ["yarn.lock"],
        };
    }
    return {
        cmd: "npm",
        args: ["outdated", "--json", "--long"],
        lockFiles: ["package-lock.json", "npm-shrinkwrap.json"],
    };
}
async function runPackageOutdated(projectPath, tempDir, tool, options = {}) {
    const persistToDisk = options.persistToDisk !== false;
    const targetFile = path_1.default.join(tempDir, `${tool}-outdated.json`);
    try {
        const { cmd, args, lockFiles } = buildOutdatedCommand(tool);
        const lockDir = await (0, utils_1.findLockDir)(projectPath, lockFiles);
        const cwd = lockDir || projectPath;
        const result = await (0, utils_1.runCommand)(cmd, args, { cwd });
        const parsed = (0, utils_1.parseJsonOutput)(result.stdout);
        const normalized = normalizeOutdatedOutput(tool, parsed);
        if (normalized && typeof normalized === "object") {
            if (persistToDisk) {
                await (0, utils_1.writeJsonFile)(targetFile, normalized);
            }
            return { ok: true, data: normalized, ...(persistToDisk ? { file: targetFile } : {}) };
        }
        if (tool === "yarn" && isYarnOutdatedUnsupported(result)) {
            if (persistToDisk) {
                await (0, utils_1.writeJsonFile)(targetFile, {
                    stdout: result.stdout,
                    stderr: result.stderr,
                    code: result.code,
                });
            }
            return {
                ok: false,
                error: 'Yarn outdated is not available in this Yarn release (common on Yarn Berry).',
                ...(persistToDisk ? { file: targetFile } : {}),
            };
        }
        if (persistToDisk) {
            await (0, utils_1.writeJsonFile)(targetFile, {
                stdout: result.stdout,
                stderr: result.stderr,
                code: result.code,
            });
        }
        return {
            ok: false,
            error: `Failed to parse ${tool} outdated output`,
            ...(persistToDisk ? { file: targetFile } : {}),
        };
    }
    catch (err) {
        if (persistToDisk) {
            await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        }
        return {
            ok: false,
            error: `${tool} outdated failed: ${String(err)}`,
            ...(persistToDisk ? { file: targetFile } : {}),
        };
    }
}
