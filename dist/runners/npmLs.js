"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runNpmLs = runNpmLs;
const path_1 = __importDefault(require("path"));
const utils_1 = require("../utils");
async function runNpmLs(projectPath, tempDir) {
    const targetFile = path_1.default.join(tempDir, 'npm-ls.json');
    try {
        const result = await (0, utils_1.runCommand)('npm', ['ls', '--json', '--all'], { cwd: projectPath });
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
        const error = result.code && result.code !== 0 ? `npm ls exited with code ${result.code}` : 'Failed to parse npm ls output';
        return { ok: false, error, file: targetFile };
    }
    catch (err) {
        await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        return { ok: false, error: `npm ls failed: ${String(err)}`, file: targetFile };
    }
}
