"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runDepcheck = runDepcheck;
const path_1 = __importDefault(require("path"));
const depcheck_1 = __importDefault(require("depcheck"));
const utils_1 = require("../utils");
async function runDepcheck(projectPath, tempDir) {
    const targetFile = path_1.default.join(tempDir, 'depcheck.json');
    try {
        const result = await (0, depcheck_1.default)(projectPath, {
            ignoreDirs: ['.dependency-radar', 'dist', 'build', 'coverage', 'node_modules']
        });
        await (0, utils_1.writeJsonFile)(targetFile, result);
        return { ok: true, data: result, file: targetFile };
    }
    catch (err) {
        await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        return { ok: false, error: `depcheck failed: ${String(err)}`, file: targetFile };
    }
}
