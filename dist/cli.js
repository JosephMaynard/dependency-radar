#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const path_1 = __importDefault(require("path"));
const aggregator_1 = require("./aggregator");
const depcheckRunner_1 = require("./runners/depcheckRunner");
const licenseChecker_1 = require("./runners/licenseChecker");
const madgeRunner_1 = require("./runners/madgeRunner");
const npmAudit_1 = require("./runners/npmAudit");
const npmLs_1 = require("./runners/npmLs");
const report_1 = require("./report");
const promises_1 = __importDefault(require("fs/promises"));
const utils_1 = require("./utils");
function parseArgs(argv) {
    const opts = {
        command: 'scan',
        project: process.cwd(),
        out: 'dependency-radar.html',
        keepTemp: false
    };
    const args = [...argv];
    if (args[0] && !args[0].startsWith('-')) {
        opts.command = args.shift();
    }
    while (args.length) {
        const arg = args.shift();
        if (!arg)
            break;
        if (arg === '--project' && args[0])
            opts.project = args.shift();
        else if (arg === '--out' && args[0])
            opts.out = args.shift();
        else if (arg === '--keep-temp')
            opts.keepTemp = true;
        else if (arg === '--help' || arg === '-h') {
            printHelp();
            process.exit(0);
        }
    }
    return opts;
}
function printHelp() {
    console.log(`dependency-radar scan [options]

Options:
  --project <path>   Project folder (default: cwd)
  --out <path>       Output HTML file (default: dependency-radar.html)
  --keep-temp        Keep .dependency-radar folder
`);
}
async function run() {
    const opts = parseArgs(process.argv.slice(2));
    if (opts.command !== 'scan') {
        printHelp();
        process.exit(1);
        return;
    }
    const projectPath = path_1.default.resolve(opts.project);
    let outputPath = path_1.default.resolve(opts.out);
    try {
        const stat = await promises_1.default.stat(outputPath).catch(() => undefined);
        if ((stat && stat.isDirectory()) || opts.out.endsWith(path_1.default.sep)) {
            outputPath = path_1.default.join(outputPath, 'dependency-radar.html');
        }
    }
    catch (e) {
        // ignore, best-effort path normalization
    }
    const tempDir = path_1.default.join(projectPath, '.dependency-radar');
    try {
        await (0, utils_1.ensureDir)(tempDir);
        console.log(`Scanning project at ${projectPath}`);
        const [auditResult, npmLsResult, licenseResult, depcheckResult, madgeResult] = await Promise.all([
            (0, npmAudit_1.runNpmAudit)(projectPath, tempDir),
            (0, npmLs_1.runNpmLs)(projectPath, tempDir),
            (0, licenseChecker_1.runLicenseChecker)(projectPath, tempDir),
            (0, depcheckRunner_1.runDepcheck)(projectPath, tempDir),
            (0, madgeRunner_1.runMadge)(projectPath, tempDir)
        ]);
        const aggregated = await (0, aggregator_1.aggregateData)({
            projectPath,
            auditResult,
            npmLsResult,
            licenseResult,
            depcheckResult,
            madgeResult
        });
        await (0, report_1.renderReport)(aggregated, outputPath);
        console.log(`Report written to ${outputPath}`);
    }
    catch (err) {
        console.error('Failed to generate report:', err);
        process.exit(1);
    }
    finally {
        if (!opts.keepTemp) {
            await (0, utils_1.removeDir)(tempDir);
        }
        else {
            console.log(`Temporary data kept at ${tempDir}`);
        }
    }
}
run();
