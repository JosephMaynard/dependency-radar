"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runPackageAudit = runPackageAudit;
const path_1 = __importDefault(require("path"));
const utils_1 = require("../utils");
function normalizeAuditOutput(tool, data) {
    var _a;
    if (!data)
        return undefined;
    if (data.vulnerabilities || data.advisories)
        return data;
    // Yarn (classic/berry) often emits JSONL with auditAdvisory entries.
    const entries = Array.isArray(data) ? data : [data];
    const advisories = {};
    for (const entry of entries) {
        if (!entry || typeof entry !== "object")
            continue;
        if (entry.type === "auditAdvisory" && ((_a = entry.data) === null || _a === void 0 ? void 0 : _a.advisory)) {
            const adv = entry.data.advisory;
            const key = String(adv.id ||
                adv.github_advisory_id ||
                `${adv.module_name || adv.module}:${adv.title || "advisory"}`);
            advisories[key] = adv;
        }
    }
    if (Object.keys(advisories).length > 0) {
        return { advisories };
    }
    if (tool === "pnpm" && data.result && data.advisories) {
        return data;
    }
    return undefined;
}
function buildAuditCommand(tool, yarnVersion) {
    if (tool === "pnpm") {
        return {
            cmd: "pnpm",
            args: ["audit", "--json"],
            lockFiles: ["pnpm-lock.yaml"],
        };
    }
    if (tool === "yarn") {
        const major = yarnVersion
            ? Number.parseInt(yarnVersion.split(".")[0], 10)
            : NaN;
        if (!Number.isNaN(major) && major >= 2) {
            return {
                cmd: "yarn",
                args: ["npm", "audit", "--all", "--json"],
                lockFiles: ["yarn.lock"],
            };
        }
        return { cmd: "yarn", args: ["audit", "--json"], lockFiles: ["yarn.lock"] };
    }
    return {
        cmd: "npm",
        args: ["audit", "--json"],
        lockFiles: ["package-lock.json", "npm-shrinkwrap.json"],
    };
}
/**
 * Run a dependency audit using the specified package manager, normalize the audit output, and optionally write the result to disk.
 *
 * @param projectPath - Path to the project whose dependencies should be audited
 * @param tempDir - Directory where the audit output file may be written
 * @param tool - Package manager to use: `"npm"`, `"pnpm"`, or `"yarn"`
 * @param yarnVersion - Optional Yarn version string used to select the correct Yarn audit command
 * @param options - Optional persistence settings; when `options.persistToDisk` is omitted or `true`, write audit output/diagnostics to `${tempDir}/${tool}-audit.json` and include `file` in the result
 * @returns An object with `ok: true` and `data` containing the normalized audit output (and `file` when persisted) on success; otherwise `ok: false` and `error` with an optional `file` when persisted
 */
async function runPackageAudit(projectPath, tempDir, tool, yarnVersion, options = {}) {
    const persistToDisk = options.persistToDisk !== false;
    const targetFile = path_1.default.join(tempDir, `${tool}-audit.json`);
    try {
        const { cmd, args, lockFiles } = buildAuditCommand(tool, yarnVersion);
        const lockDir = await (0, utils_1.findLockDir)(projectPath, lockFiles);
        const cwd = lockDir || projectPath;
        const result = await (0, utils_1.runCommand)(cmd, args, { cwd });
        const parsed = (0, utils_1.parseJsonOutput)(result.stdout);
        const normalized = normalizeAuditOutput(tool, parsed);
        if (normalized) {
            if (persistToDisk) {
                await (0, utils_1.writeJsonFile)(targetFile, normalized);
            }
            return {
                ok: true,
                data: normalized,
                contextPath: cwd,
                ...(persistToDisk ? { file: targetFile } : {})
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
            error: `Failed to parse ${tool} audit output`,
            contextPath: cwd,
            ...(persistToDisk ? { file: targetFile } : {}),
        };
    }
    catch (err) {
        if (persistToDisk) {
            await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        }
        return {
            ok: false,
            error: `${tool} audit failed: ${String(err)}`,
            ...(persistToDisk ? { file: targetFile } : {}),
        };
    }
}
