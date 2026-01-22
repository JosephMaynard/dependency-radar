#!/usr/bin/env node
import path from 'path';
import { aggregateData } from './aggregator';
import { runDepcheck } from './runners/depcheckRunner';
import { runLicenseChecker } from './runners/licenseChecker';
import { runMadge } from './runners/madgeRunner';
import { runNpmAudit } from './runners/npmAudit';
import { runNpmLs } from './runners/npmLs';
import { renderReport } from './report';
import fs from 'fs/promises';
import { ensureDir, removeDir } from './utils';

interface CliOptions {
  command: 'scan';
  project: string;
  out: string;
  keepTemp: boolean;
  maintenance: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    command: 'scan',
    project: process.cwd(),
    out: 'dependency-radar.html',
    keepTemp: false,
    maintenance: false
  };

  const args = [...argv];
  if (args[0] && !args[0].startsWith('-')) {
    opts.command = args.shift() as 'scan';
  }

  while (args.length) {
    const arg = args.shift();
    if (!arg) break;
    if (arg === '--project' && args[0]) opts.project = args.shift()!;
    else if (arg === '--out' && args[0]) opts.out = args.shift()!;
    else if (arg === '--keep-temp') opts.keepTemp = true;
    else if (arg === '--maintenance') opts.maintenance = true;
    else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    }
  }

  return opts;
}

function printHelp(): void {
  console.log(`dependency-radar scan [options]

Options:
  --project <path>   Project folder (default: cwd)
  --out <path>       Output HTML file (default: dependency-radar.html)
  --keep-temp        Keep .dependency-radar folder
  --maintenance      Enable slow maintenance checks (npm registry calls)
`);
}

async function run(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.command !== 'scan') {
    printHelp();
    process.exit(1);
    return;
  }

  const projectPath = path.resolve(opts.project);
  let outputPath = path.resolve(opts.out);
  const startTime = Date.now();
  let dependencyCount = 0;
  try {
    const stat = await fs.stat(outputPath).catch(() => undefined);
    if ((stat && stat.isDirectory()) || opts.out.endsWith(path.sep)) {
      outputPath = path.join(outputPath, 'dependency-radar.html');
    }
  } catch (e) {
    // ignore, best-effort path normalization
  }
  const tempDir = path.join(projectPath, '.dependency-radar');

  const stopSpinner = startSpinner(`Scanning project at ${projectPath}`);
  try {
    await ensureDir(tempDir);

    const [auditResult, npmLsResult, licenseResult, depcheckResult, madgeResult] = await Promise.all([
      runNpmAudit(projectPath, tempDir),
      runNpmLs(projectPath, tempDir),
      runLicenseChecker(projectPath, tempDir),
      runDepcheck(projectPath, tempDir),
      runMadge(projectPath, tempDir)
    ]);

    if (opts.maintenance) {
      stopSpinner(true);
      console.log('Running maintenance checks (slow mode)');
      console.log('This may take several minutes depending on dependency count.');
    }

    const aggregated = await aggregateData({
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

    await renderReport(aggregated, outputPath);
    stopSpinner(true);
    console.log(`Report written to ${outputPath}`);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`Scan complete: ${dependencyCount} dependencies analysed in ${elapsed}s`);
  } catch (err: any) {
    stopSpinner(false);
    console.error('Failed to generate report:', err);
    process.exit(1);
  } finally {
    if (!opts.keepTemp) {
      await removeDir(tempDir);
    } else {
      console.log(`Temporary data kept at ${tempDir}`);
    }
  }
}

run();

function startSpinner(text: string): (success?: boolean) => void {
  const frames = ['|', '/', '-', '\\'];
  let i = 0;
  process.stdout.write(`${frames[i]} ${text}`);
  const timer = setInterval(() => {
    i = (i + 1) % frames.length;
    process.stdout.write(`\r${frames[i]} ${text}`);
  }, 120);

  let stopped = false;

  return (success = true) => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    process.stdout.write(`\r${success ? '✔' : '✖'} ${text}\n`);
  };
}
