"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runNpmOutdated = runNpmOutdated;
const path_1 = __importDefault(require("path"));
const utils_1 = require("../utils");
async function runNpmOutdated(projectPath, tempDir) {
    const targetFile = path_1.default.join(tempDir, 'npm-outdated.json');
    try {
        const result = await (0, utils_1.runCommand)('npm', ['outdated', '--json', '--long'], { cwd: projectPath });
        let parsed;
        try {
            parsed = JSON.parse(result.stdout || '{}');
        }
        catch (err) {
            parsed = undefined;
        }
        if (parsed && typeof parsed === 'object') {
            await (0, utils_1.writeJsonFile)(targetFile, parsed);
            return { ok: true, data: parsed, file: targetFile };
        }
        await (0, utils_1.writeJsonFile)(targetFile, { stdout: result.stdout, stderr: result.stderr, code: result.code });
        return { ok: false, error: 'Failed to parse npm outdated output', file: targetFile };
    }
    catch (err) {
        await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        return { ok: false, error: `npm outdated failed: ${String(err)}`, file: targetFile };
    }
}
