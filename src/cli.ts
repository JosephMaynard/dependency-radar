#!/usr/bin/env node
import path from 'path';
import { aggregateData } from './aggregator';
import { runImportGraph } from './runners/importGraphRunner';
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
  audit: boolean;
  json: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    command: 'scan',
    project: process.cwd(),
    out: 'dependency-radar.html',
    keepTemp: false,
    maintenance: false,
    audit: true,
    json: false
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
    else if (arg === '--no-audit') opts.audit = false;
    else if (arg === '--json') opts.json = true;
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
  --json             Write aggregated data to JSON (default filename: dependency-radar.json)
  --keep-temp        Keep .dependency-radar folder
  --maintenance      Enable slow maintenance checks (npm registry calls)
  --no-audit         Skip npm audit (useful for offline scans)
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
  if (opts.json && opts.out === 'dependency-radar.html') {
    opts.out = 'dependency-radar.json';
  }
  let outputPath = path.resolve(opts.out);
  const startTime = Date.now();
  let dependencyCount = 0;
  try {
    const stat = await fs.stat(outputPath).catch(() => undefined);
    const endsWithSeparator = opts.out.endsWith('/') || opts.out.endsWith('\\');
    const hasExtension = Boolean(path.extname(outputPath));
    if ((stat && stat.isDirectory()) || endsWithSeparator || (!stat && !hasExtension)) {
      outputPath = path.join(outputPath, opts.json ? 'dependency-radar.json' : 'dependency-radar.html');
    }
  } catch (e) {
    // ignore, best-effort path normalization
  }
  const tempDir = path.join(projectPath, '.dependency-radar');

  const stopSpinner = startSpinner(`Scanning project at ${projectPath}`);
  try {
    await ensureDir(tempDir);

    const [auditResult, npmLsResult, importGraphResult] = await Promise.all([
      opts.audit ? runNpmAudit(projectPath, tempDir) : Promise.resolve(undefined),
      runNpmLs(projectPath, tempDir),
      runImportGraph(projectPath, tempDir)
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
      importGraphResult
    });
    dependencyCount = aggregated.dependencies.length;

    if (opts.maintenance) {
      process.stdout.write('\n');
    }

    if (opts.json) {
      await fs.mkdir(path.dirname(outputPath), { recursive: true });
      await fs.writeFile(outputPath, JSON.stringify(aggregated, null, 2), 'utf8');
    } else {
      await renderReport(aggregated, outputPath);
    }
    stopSpinner(true);
    console.log(`${opts.json ? 'JSON' : 'Report'} written to ${outputPath}`);
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
  
  // Always show CTA as the last output
  console.log('');
  console.log('Get additional risk analysis and a management-ready summary at https://dependency-radar.com');
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
