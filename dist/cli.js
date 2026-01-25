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
        keepTemp: false,
        maintenance: false,
        audit: true
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
        else if (arg === '--maintenance')
            opts.maintenance = true;
        else if (arg === '--no-audit')
            opts.audit = false;
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
  --maintenance      Enable slow maintenance checks (npm registry calls)
  --no-audit         Skip npm audit (useful for offline scans)
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
    const startTime = Date.now();
    let dependencyCount = 0;
    try {
        const stat = await promises_1.default.stat(outputPath).catch(() => undefined);
        const endsWithSeparator = opts.out.endsWith('/') || opts.out.endsWith('\\');
        const hasExtension = Boolean(path_1.default.extname(outputPath));
        if ((stat && stat.isDirectory()) || endsWithSeparator || (!stat && !hasExtension)) {
            outputPath = path_1.default.join(outputPath, 'dependency-radar.html');
        }
    }
    catch (e) {
        // ignore, best-effort path normalization
    }
    const tempDir = path_1.default.join(projectPath, '.dependency-radar');
    const stopSpinner = startSpinner(`Scanning project at ${projectPath}`);
    try {
        await (0, utils_1.ensureDir)(tempDir);
        const [auditResult, npmLsResult, licenseResult, depcheckResult, madgeResult] = await Promise.all([
            opts.audit ? (0, npmAudit_1.runNpmAudit)(projectPath, tempDir) : Promise.resolve(undefined),
            (0, npmLs_1.runNpmLs)(projectPath, tempDir),
            (0, licenseChecker_1.runLicenseChecker)(projectPath, tempDir),
            (0, depcheckRunner_1.runDepcheck)(projectPath, tempDir),
            (0, madgeRunner_1.runMadge)(projectPath, tempDir)
        ]);
        if (opts.maintenance) {
            stopSpinner(true);
            console.log('Running maintenance checks (slow mode)');
            console.log('This may take several minutes depending on dependency count.');
        }
        const aggregated = await (0, aggregator_1.aggregateData)({
            projectPath,
            maintenanceEnabled: opts.maintenance,
            onMaintenanceProgress: opts.maintenance
                ? (current, total, name) => {
                    process.stdout.write(`\r[${current}/${total}] ${name}                      `);
                }
                : undefined,
            auditResult,
            npmLsResult,
            licenseResult,
            depcheckResult,
            madgeResult
        });
        dependencyCount = aggregated.dependencies.length;
        if (opts.maintenance) {
            process.stdout.write('\n');
        }
        await (0, report_1.renderReport)(aggregated, outputPath);
        stopSpinner(true);
        console.log(`Report written to ${outputPath}`);
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        console.log(`Scan complete: ${dependencyCount} dependencies analysed in ${elapsed}s`);
    }
    catch (err) {
        stopSpinner(false);
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
    // Always show CTA as the last output
    console.log('');
    console.log('Get additional risk analysis and a management-ready summary at https://dependency-radar.com');
}
run();
function startSpinner(text) {
    const frames = ['|', '/', '-', '\\'];
    let i = 0;
    process.stdout.write(`${frames[i]} ${text}`);
    const timer = setInterval(() => {
        i = (i + 1) % frames.length;
        process.stdout.write(`\r${frames[i]} ${text}`);
    }, 120);
    let stopped = false;
    return (success = true) => {
        if (stopped)
            return;
        stopped = true;
        clearInterval(timer);
        process.stdout.write(`\r${success ? '✔' : '✖'} ${text}\n`);
    };
}
