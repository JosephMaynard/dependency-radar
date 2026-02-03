"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runPackageAudit = runPackageAudit;
const path_1 = __importDefault(require("path"));
const promises_1 = __importDefault(require("fs/promises"));
const utils_1 = require("../utils");
async function pathExists(target) {
    try {
        await promises_1.default.stat(target);
        return true;
    }
    catch {
        return false;
    }
}
async function findLockDir(startPath, lockFiles) {
    let current = startPath;
    while (true) {
        for (const file of lockFiles) {
            if (await pathExists(path_1.default.join(current, file))) {
                return current;
            }
        }
        const parent = path_1.default.dirname(current);
        if (parent === current)
            break;
        current = parent;
    }
    return undefined;
}
function parseJsonOutput(raw) {
    if (!raw)
        return undefined;
    try {
        return JSON.parse(raw);
    }
    catch {
        const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
        const parsed = [];
        for (const line of lines) {
            try {
                parsed.push(JSON.parse(line));
            }
            catch {
                // ignore non-JSON lines
            }
        }
        return parsed.length > 0 ? parsed : undefined;
    }
}
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
        if (!entry || typeof entry !== 'object')
            continue;
        if (entry.type === 'auditAdvisory' && ((_a = entry.data) === null || _a === void 0 ? void 0 : _a.advisory)) {
            const adv = entry.data.advisory;
            const key = String(adv.id || adv.github_advisory_id || `${adv.module_name || adv.module}:${adv.title || 'advisory'}`);
            advisories[key] = adv;
        }
    }
    if (Object.keys(advisories).length > 0) {
        return { advisories };
    }
    if (tool === 'pnpm' && data.result && data.advisories) {
        return data;
    }
    return undefined;
}
function buildAuditCommand(tool, yarnVersion) {
    if (tool === 'pnpm') {
        return { cmd: 'pnpm', args: ['audit', '--json'], lockFiles: ['pnpm-lock.yaml'] };
    }
    if (tool === 'yarn') {
        const major = yarnVersion ? Number.parseInt(yarnVersion.split('.')[0], 10) : NaN;
        if (!Number.isNaN(major) && major >= 2) {
            return { cmd: 'yarn', args: ['npm', 'audit', '--all', '--json'], lockFiles: ['yarn.lock'] };
        }
        return { cmd: 'yarn', args: ['audit', '--json'], lockFiles: ['yarn.lock'] };
    }
    return { cmd: 'npm', args: ['audit', '--json'], lockFiles: ['package-lock.json', 'npm-shrinkwrap.json'] };
}
async function runPackageAudit(projectPath, tempDir, tool, yarnVersion) {
    const targetFile = path_1.default.join(tempDir, `${tool}-audit.json`);
    try {
        const { cmd, args, lockFiles } = buildAuditCommand(tool, yarnVersion);
        const lockDir = await findLockDir(projectPath, lockFiles);
        const cwd = lockDir || projectPath;
        const result = await (0, utils_1.runCommand)(cmd, args, { cwd });
        const parsed = parseJsonOutput(result.stdout);
        const normalized = normalizeAuditOutput(tool, parsed);
        if (normalized) {
            await (0, utils_1.writeJsonFile)(targetFile, normalized);
            return { ok: true, data: normalized, file: targetFile };
        }
        await (0, utils_1.writeJsonFile)(targetFile, { stdout: result.stdout, stderr: result.stderr, code: result.code });
        return { ok: false, error: `Failed to parse ${tool} audit output`, file: targetFile };
    }
    catch (err) {
        await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        return { ok: false, error: `${tool} audit failed: ${String(err)}`, file: targetFile };
    }
}
