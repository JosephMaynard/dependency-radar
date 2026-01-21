"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runLicenseChecker = runLicenseChecker;
const path_1 = __importDefault(require("path"));
const utils_1 = require("../utils");
async function runLicenseChecker(projectPath, tempDir) {
    const targetFile = path_1.default.join(tempDir, 'license-checker.json');
    const bin = (0, utils_1.findBin)(projectPath, 'license-checker');
    try {
        const result = await (0, utils_1.runCommand)(bin, ['--json', '--production', '--development'], { cwd: projectPath });
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
        const error = result.code && result.code !== 0 ? `license-checker exited with code ${result.code}` : 'Failed to parse license-checker output';
        return { ok: false, error, file: targetFile };
    }
    catch (err) {
        await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        return { ok: false, error: `license-checker failed: ${String(err)}`, file: targetFile };
    }
}
