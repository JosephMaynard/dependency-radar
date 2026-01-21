"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runNpmAudit = runNpmAudit;
const path_1 = __importDefault(require("path"));
const utils_1 = require("../utils");
async function runNpmAudit(projectPath, tempDir) {
    const targetFile = path_1.default.join(tempDir, 'npm-audit.json');
    try {
        const result = await (0, utils_1.runCommand)('npm', ['audit', '--json'], { cwd: projectPath });
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
