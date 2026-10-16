'use strict';

// Turns the one JSON report the scan step wrote into everything else the
// action needs: the Scorecard SVG, a PNG of it, the HTML report, optional
// SARIF, and summary.json (the headline figures for the comment).
//
// It renders with the installed dependency-radar package's own modules, so
// one scan feeds every output and the figures match what `dependency-radar
// slide` would print for the same scan. If a future CLI version moves those
// modules, it falls back to running the CLI commands (one extra scan each).

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { pathToFileURL } = require('url');
const { env, bool, warning, setOutput } = require('./lib/github');

const packageDir = env('DR_PACKAGE_DIR');
const cliPath = env('DR_CLI', packageDir ? path.join(packageDir, 'dist', 'cli.js') : '');
const outDir = env('DR_OUT_DIR');
const jsonPath = env('DR_JSON', outDir ? path.join(outDir, 'dependency-radar.json') : '');
const theme = env('DR_THEME', 'dark') === 'light' ? 'light' : 'dark';
const wantPng = bool('DR_PNG', true);
const wantHtml = bool('DR_HTML', true);
const wantSarif = bool('DR_SARIF', false);

if (!packageDir || !outDir) {
  console.error('render.js needs DR_PACKAGE_DIR and DR_OUT_DIR.');
  process.exit(2);
}
fs.mkdirSync(outDir, { recursive: true });

const svgPath = path.join(outDir, 'dependency-radar-slide.svg');
const pngPath = path.join(outDir, 'dependency-radar-slide.png');
const htmlPath = path.join(outDir, 'dependency-radar.html');
const sarifPath = path.join(outDir, 'dependency-radar.sarif');
const summaryPath = path.join(outDir, 'summary.json');

function tryRequire(relative) {
  try {
    return require(path.join(packageDir, relative));
  } catch (err) {
    return null;
  }
}

function run(file, args, options) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(file, args, Object.assign({ stdio: 'ignore' }, options || {}));
    } catch (err) {
      resolve(false);
      return;
    }
    const timer = setTimeout(() => {
      child.kill();
      const escalate = setTimeout(() => child.kill('SIGKILL'), 5000);
      child.once('exit', () => clearTimeout(escalate));
      resolve(false);
    }, (options && options.timeoutMs) || 60000);
    child.on('error', () => {
      clearTimeout(timer);
      resolve(false);
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      resolve(code === 0);
    });
  });
}

// The same flags the scan step used, for the fallback commands.
function scanFlags() {
  const flags = ['--project', env('DR_PROJECT', '.'), '--quiet'];
  if (bool('DR_OFFLINE', false)) flags.push('--offline');
  if (bool('DR_NO_MAINTENANCE', false)) flags.push('--no-maintenance');
  return flags;
}

// Rasteriser probe. Mirrors slideRasterisers() in src/cli.ts, plus
// CHROME_BIN (set on GitHub's hosted runners).
function rasterisers() {
  const list = [];
  if (process.env.CHROME_PATH) list.push({ file: process.env.CHROME_PATH, kind: 'chromium' });
  if (process.env.CHROME_BIN) list.push({ file: process.env.CHROME_BIN, kind: 'chromium' });
  if (process.platform === 'darwin') {
    list.push(
      { file: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', kind: 'chromium' },
      { file: '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge', kind: 'chromium' },
      { file: '/Applications/Chromium.app/Contents/MacOS/Chromium', kind: 'chromium' }
    );
  } else if (process.platform === 'win32') {
    const roots = [process.env.PROGRAMFILES, process.env['PROGRAMFILES(X86)'], process.env.LOCALAPPDATA].filter(Boolean);
    for (const root of roots) {
      list.push(
        { file: path.join(root, 'Google', 'Chrome', 'Application', 'chrome.exe'), kind: 'chromium' },
        { file: path.join(root, 'Microsoft', 'Edge', 'Application', 'msedge.exe'), kind: 'chromium' }
      );
    }
  } else {
    for (const name of ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'microsoft-edge']) {
      list.push({ file: name, kind: 'chromium' });
    }
  }
  list.push({ file: 'rsvg-convert', kind: 'rsvg' });
  return list;
}

async function renderPng(svg) {
  const wrapperPath = svgPath + '.render.html';
  const wrapper =
    '<!doctype html><html><head><meta charset="utf-8"><style>' +
    'html,body{margin:0;padding:0;overflow:hidden}' +
    'svg{display:block;width:100vw;height:100vh}' +
    '</style></head><body>' + svg + '</body></html>';
  const exists = () => fs.existsSync(pngPath) && fs.statSync(pngPath).size > 0;

  for (const candidate of rasterisers()) {
    if (candidate.kind === 'rsvg') {
      if (await run(candidate.file, ['-w', '1920', '-h', '1080', svgPath, '-o', pngPath]) && exists()) return true;
      continue;
    }
    if (path.isAbsolute(candidate.file) && !fs.existsSync(candidate.file)) continue;
    fs.writeFileSync(wrapperPath, wrapper, 'utf8');
    const args = [
      '--headless',
      '--disable-gpu',
      '--hide-scrollbars',
      '--window-size=1920,1080',
      '--screenshot=' + pngPath,
      pathToFileURL(wrapperPath).href,
    ];
    try {
      if (await run(candidate.file, args) && exists()) return true;
      // Ubuntu 24.04 restricts unprivileged user namespaces, which can stop
      // Chrome's sandbox from starting on CI runners. The page is a local SVG
      // the action just wrote, with no scripts, so retry without the sandbox.
      if (process.platform === 'linux') {
        if (await run(candidate.file, ['--no-sandbox'].concat(args)) && exists()) return true;
      }
    } finally {
      try { fs.unlinkSync(wrapperPath); } catch (err) { /* already gone */ }
    }
  }
  return false;
}

// Headline figures for the comment table. Uses the slide model when it is
// available so the table and the image never disagree.
function buildSummary(data, model, formatBytes) {
  const summary = {
    toolVersion: data.dependencyRadarVersion || '',
    projectName: (data.project && data.project.name) || '',
    generatedAt: data.generatedAt || '',
    dependencyCount: data.summary ? data.summary.dependencyCount : 0,
    directCount: data.summary ? data.summary.directCount : 0,
    transitiveCount: data.summary ? data.summary.transitiveCount : 0,
    treeIncomplete: false,
    installSize: '',
    measuredPackageCount: 0,
    metrics: null,
  };
  if (!model) return summary;
  summary.projectName = model.projectName || summary.projectName;
  summary.treeIncomplete = Boolean(model.treeIncomplete);
  summary.measuredPackageCount = model.measuredPackageCount || 0;
  if (model.totalInstallBytes >= 0 && formatBytes) summary.installSize = formatBytes(model.totalInstallBytes);
  summary.metrics = {
    vulnerabilities: model.vulnerabilities,
    maintenance: model.maintenance,
    licenses: model.licenses,
    blockers: model.blockers,
    duplicates: model.duplicates,
  };
  return summary;
}

async function main() {
  let data = null;
  if (jsonPath && fs.existsSync(jsonPath)) {
    try {
      data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    } catch (err) {
      warning('Could not parse ' + jsonPath + ': ' + err.message);
    }
  }
  if (!data) {
    // The CLI writes no JSON when it finds no dependencies or the scan
    // failed outright. Nothing to draw; the comment explains.
    fs.writeFileSync(summaryPath, JSON.stringify({ missing: true }, null, 2));
    setOutput('summary-path', summaryPath);
    return;
  }

  const slideModel = tryRequire('dist/slide/slideModel.js');
  const slideSvg = tryRequire('dist/slide/slideSvg.js');
  const report = tryRequire('dist/report.js');
  const formats = tryRequire('dist/outputFormats.js');

  let model = null;
  let svg = '';
  if (slideModel && slideSvg && slideModel.buildSlideModel && slideSvg.buildSlideSvg) {
    model = slideModel.buildSlideModel(data);
    svg = slideSvg.buildSlideSvg(model, theme);
    fs.writeFileSync(svgPath, svg, 'utf8');
  } else {
    warning('This dependency-radar version has no slide modules to import; running `slide` separately.');
    const args = [cliPath, 'slide', '--out', svgPath].concat(scanFlags());
    if (theme === 'light') args.push('--light-mode');
    if (wantPng) args.push('--png');
    await run(process.execPath, args, { stdio: 'inherit', timeoutMs: 15 * 60000 });
    if (fs.existsSync(svgPath)) svg = fs.readFileSync(svgPath, 'utf8');
  }

  if (svg) {
    setOutput('svg-path', svgPath);
    if (wantPng) {
      const havePng = fs.existsSync(pngPath) || (await renderPng(svg));
      if (havePng) setOutput('png-path', pngPath);
      else warning('No PNG: no Chrome, Edge, Chromium or rsvg-convert found on this runner. The SVG is used instead.');
    }
  } else {
    warning('The Scorecard SVG could not be produced.');
  }

  if (wantHtml) {
    if (report && report.renderReport) {
      await report.renderReport(data, htmlPath);
    } else {
      await run(process.execPath, [cliPath, 'scan', '--out', htmlPath].concat(scanFlags()), { stdio: 'inherit', timeoutMs: 15 * 60000 });
    }
    if (fs.existsSync(htmlPath)) setOutput('html-path', htmlPath);
  }

  if (wantSarif) {
    if (formats && formats.renderSarif) {
      fs.writeFileSync(sarifPath, formats.renderSarif(data), 'utf8');
    } else {
      await run(process.execPath, [cliPath, 'scan', '--format', 'sarif', '--out', sarifPath].concat(scanFlags()), { stdio: 'inherit', timeoutMs: 15 * 60000 });
    }
    if (fs.existsSync(sarifPath)) setOutput('sarif-path', sarifPath);
  }

  const summary = buildSummary(data, model, slideSvg && slideSvg.formatSlideBytes);
  fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));
  setOutput('summary-path', summaryPath);
}

main().catch((err) => {
  // Rendering problems should not hide the scan result, so report and carry
  // on. The publish step still comments with whatever exists.
  warning('Rendering failed: ' + (err && err.stack ? err.stack : err));
  if (!fs.existsSync(summaryPath)) fs.writeFileSync(summaryPath, JSON.stringify({ missing: true }, null, 2));
  setOutput('summary-path', summaryPath);
});
