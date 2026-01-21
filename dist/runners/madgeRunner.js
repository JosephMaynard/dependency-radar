"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runMadge = runMadge;
const path_1 = __importDefault(require("path"));
const madge_1 = __importDefault(require("madge"));
const utils_1 = require("../utils");
async function runMadge(projectPath, tempDir) {
    const targetFile = path_1.default.join(tempDir, 'madge.json');
    try {
        const srcPath = path_1.default.join(projectPath, 'src');
        const hasSrc = await (0, utils_1.pathExists)(srcPath);
        const entry = hasSrc ? srcPath : projectPath;
        const result = await (0, madge_1.default)(entry, {
            baseDir: projectPath,
            includeNpm: true,
            excludeRegExp: [/node_modules/, /dist/, /build/, /coverage/, /.dependency-radar/]
        });
        const graph = await result.obj();
        await (0, utils_1.writeJsonFile)(targetFile, graph);
        return { ok: true, data: graph, file: targetFile };
    }
    catch (err) {
        await (0, utils_1.writeJsonFile)(targetFile, { error: String(err) });
        return { ok: false, error: `madge failed: ${String(err)}`, file: targetFile };
    }
}
