"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runNpmAudit = runNpmAudit;
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
async function runNpmAudit(projectPath, tempDir) {
    const targetFile = path_1.default.join(tempDir, 'npm-audit.json');
    try {
        const pnpmLockDir = await findLockDir(projectPath, ['pnpm-lock.yaml']);
        const npmLockDir = pnpmLockDir ? undefined : await findLockDir(projectPath, ['package-lock.json', 'npm-shrinkwrap.json']);
        const tool = pnpmLockDir ? 'pnpm' : 'npm';
        const cwd = pnpmLockDir || npmLockDir || projectPath;
        const result = await (0, utils_1.runCommand)(tool, ['audit', '--json'], { cwd });
        let parsed;
        try {
            parsed = JSON.parse(result.stdout || '{}');
        }
        catch (err) {
            parsed = undefined;
        }
        if (parsed) {
            await (0, utils_1.writeJsonFile)(targetFile, parsed);
            return { ok: true, data: parsed, file: targetFile };
        }
        await (0, utils_1.writeJsonFile)(targetFile, { stdout: result.stdout, stderr: result.stderr, code: result.code });
        return { ok: false, error: 'Failed to parse npm audit output', file: targetFile };
    }
    catch (err) {
        await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        return { ok: false, error: `npm audit failed: ${String(err)}`, file: targetFile };
    }
}
