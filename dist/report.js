"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderReport = renderReport;
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
async function renderReport(data, outputPath) {
    const html = buildHtml(data);
    await promises_1.default.mkdir(path_1.default.dirname(outputPath), { recursive: true });
    await promises_1.default.writeFile(outputPath, html, 'utf8');
}
function buildHtml(data) {
    const json = JSON.stringify(data).replace(/</g, '\\u003c');
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Dependency Radar</title>
  <style>
    :root {
      --green: #2f855a;
      --amber: #b7791f;
      --red: #c53030;
      --gray: #4a5568;
      --bg: #f7fafc;
      --text: #1a202c;
      --muted: #718096;
      --border: #e2e8f0;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 20px;
    }
    h1 { margin-top: 0; }
    .controls { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; }
    .controls label { font-size: 14px; color: var(--muted); }
    input, select { padding: 6px 8px; border: 1px solid var(--border); border-radius: 6px; }
    .grid { display: flex; flex-direction: column; gap: 8px; }
    details { background: white; border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
    summary { cursor: pointer; display: flex; align-items: center; gap: 8px; list-style: none; }
    summary::-webkit-details-marker { display: none; }
    .name { font-weight: 600; }
    .badges { display: flex; flex-wrap: wrap; gap: 6px; }
    .badge { padding: 2px 8px; border-radius: 999px; font-size: 12px; color: white; display: inline-block; }
    .badge.green { background: var(--green); }
    .badge.amber { background: var(--amber); }
    .badge.red { background: var(--red); }
    .badge.gray { background: var(--gray); }
    .section { margin-top: 8px; }
    .section h4 { margin: 6px 0; }
    .pill { background: #edf2f7; color: var(--muted); padding: 2px 6px; border-radius: 6px; font-size: 12px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { text-align: left; border-bottom: 1px solid var(--border); padding: 6px 4px; font-size: 13px; }
    pre { background: #f1f5f9; padding: 10px; border-radius: 6px; overflow: auto; }
    .tool-errors { margin-bottom: 16px; padding: 10px; border: 1px solid var(--red); background: #fff5f5; color: var(--red); border-radius: 6px; }
    .kv { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 12px; }
    .kv-row { display: flex; justify-content: space-between; align-items: center; gap: 6px; margin: 0; }
    .kv-label { font-weight: 600; color: var(--muted); font-size: 13px; }
    .kv-value { font-size: 13px; }
    .info { margin-left: 4px; cursor: help; color: var(--muted); font-weight: 700; }
  </style>
</head>
<body>
  <h1>Dependency Radar</h1>
  <p>Project: <strong>${data.projectPath}</strong> · Generated at ${data.generatedAt}</p>
  ${renderToolErrors(data)}
  <div class="controls">
    <label>Search <input type="search" id="search" placeholder="name or license" /></label>
    <label>Directness
      <select id="direct-filter">
        <option value="all">All</option>
        <option value="direct">Direct</option>
        <option value="transitive">Transitive</option>
      </select>
    </label>
    <label>Runtime class
      <select id="runtime-filter">
        <option value="all">All</option>
        <option value="runtime">Runtime</option>
        <option value="build-time">Build-time</option>
        <option value="dev-only">Dev-only</option>
      </select>
    </label>
    <label>License risk
      <select id="license-filter">
        <option value="all">All</option>
        <option value="green">Green</option>
        <option value="amber">Amber</option>
        <option value="red">Red</option>
      </select>
    </label>
    <label>Sort by
      <select id="sort-by">
        <option value="name">Name</option>
        <option value="severity">Severity</option>
        <option value="depth">Depth</option>
      </select>
    </label>
    <label><input type="checkbox" id="has-vulns" /> Has vulnerabilities</label>
    <label><input type="checkbox" id="unused-only" /> Unused only</label>
  </div>
  <div id="list" class="grid"></div>
  <script type="application/json" id="radar-data">${json}</script>
  <script>
    const dataEl = document.getElementById('radar-data');
    const report = JSON.parse(dataEl.textContent || '{}');
    const maintenanceEnabled = Boolean(report.maintenanceEnabled);
    const container = document.getElementById('list');

    const controls = {
      search: document.getElementById('search'),
      direct: document.getElementById('direct-filter'),
      runtime: document.getElementById('runtime-filter'),
      license: document.getElementById('license-filter'),
      sort: document.getElementById('sort-by'),
      hasVulns: document.getElementById('has-vulns'),
      unusedOnly: document.getElementById('unused-only')
    };

    function highestSeverity(dep) {
      return dep.vulnerabilities?.highestSeverity || 'none';
    }

    const severityOrder = { none: 0, low: 1, moderate: 2, high: 3, critical: 4 };

    function formatBytes(bytes) {
      if (!bytes) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB'];
      let val = bytes;
      let unit = 0;
      while (val >= 1024 && unit < units.length - 1) {
        val /= 1024;
        unit++;
      }
      return val.toFixed(val >= 10 ? 0 : 1) + ' ' + units[unit];
    }

    function yesNo(flag) {
      return flag ? 'Yes' : 'No';
    }

    function infoIcon(text) {
      return '<span class="info" title="' + text + '">ⓘ</span>';
    }

    function renderRow(title, value, desc) {
      return '<p class="kv-row"><span class="kv-label">' + title + infoIcon(desc) + '</span><span class="kv-value">' + value + '</span></p>';
    }

    function renderSection(title, desc, bodyHtml) {
      return '<div class="section"><h4>' + title + infoIcon(desc) + '</h4>' + bodyHtml + '</div>';
    }

    function renderKvSection(title, desc, rows) {
      return renderSection(title, desc, '<div class="kv">' + rows.join('') + '</div>');
    }

    function applyFilters() {
      const term = (controls.search.value || '').toLowerCase();
      const directFilter = controls.direct.value;
      const runtimeFilter = controls.runtime.value;
      const licenseFilter = controls.license.value;
      const hasVulns = controls.hasVulns.checked;
      const unusedOnly = controls.unusedOnly.checked;

      return report.dependencies.filter((dep) => {
        if (term && !(dep.name.toLowerCase().includes(term) || (dep.license.license || '').toLowerCase().includes(term))) return false;
        if (directFilter === 'direct' && !dep.direct) return false;
        if (directFilter === 'transitive' && dep.direct) return false;
        if (runtimeFilter !== 'all' && dep.runtimeClass !== runtimeFilter) return false;
        if (licenseFilter !== 'all' && dep.licenseRisk !== licenseFilter) return false;
        if (hasVulns && severityOrder[highestSeverity(dep)] === 0) return false;
        if (unusedOnly && dep.usage.status !== 'unused') return false;
        return true;
      });
    }

    function sortDeps(deps) {
      const sortBy = controls.sort.value;
      const sorted = [...deps];
      if (sortBy === 'name') sorted.sort((a, b) => a.name.localeCompare(b.name));
      if (sortBy === 'depth') sorted.sort((a, b) => a.depth - b.depth);
      if (sortBy === 'severity') sorted.sort((a, b) => severityOrder[highestSeverity(b)] - severityOrder[highestSeverity(a)]);
      return sorted;
    }

    function badge(text, tone) {
      return '<span class="badge ' + tone + '">' + text + '</span>';
    }

    function renderDep(dep) {
      const licenseText = dep.license.license || 'Unknown';
      const severity = highestSeverity(dep);
      const badges = [
        badge(dep.direct ? 'Direct' : 'Transitive', dep.direct ? 'green' : 'amber'),
        badge(dep.runtimeClass, dep.runtimeClass === 'runtime' ? 'green' : dep.runtimeClass === 'build-time' ? 'amber' : 'gray'),
        badge('License: ' + licenseText, dep.licenseRisk),
        badge('Vulns: ' + severity, dep.vulnRisk),
        badge('Usage: ' + dep.usage.status, dep.usage.status === 'unused' ? 'red' : dep.usage.status === 'used' ? 'green' : 'gray')
      ];
      if (maintenanceEnabled) {
        badges.splice(4, 0, badge('Maintenance', dep.maintenanceRisk === 'unknown' ? 'gray' : dep.maintenanceRisk));
      }

      const summary = [
        '<summary>',
          '<span class="name">' + dep.name + '@' + dep.version + '</span>',
          '<div class="badges">',
            badges.join(''),
          '</div>',
        '</summary>'
      ].join('');

      const vulnRows = dep.vulnerabilities.items.map((v) => '<tr><td>' + v.title + '</td><td>' + v.severity + '</td><td>' + (v.vulnerableRange || '') + '</td><td><a href="' + (v.url || '#') + '">link</a></td></tr>').join('');
      const vulnTable = dep.vulnerabilities.items.length ? '<table><thead><tr><th>Title</th><th>Severity</th><th>Range</th><th>Ref</th></tr></thead><tbody>' + vulnRows + '</tbody></table>' : '<p>No advisories.</p>';

      const rawJson = JSON.stringify(dep, null, 2);

      const overviewSection = renderKvSection('Overview', 'Dependency position and runtime classification.', [
        renderRow('Depth', String(dep.depth), 'Depth of this dependency within the tree.'),
        renderRow('Parents', dep.parents.join(', ') || 'root', 'Immediate parents in the dependency tree.'),
        renderRow('Runtime Class', dep.runtimeClass + ' (' + dep.runtimeReason + ')', 'Runtime usage classification for this dependency.')
      ]);

      const licenseSection = renderKvSection('License', 'Declared license data for this dependency.', [
        renderRow('License', licenseText, 'License declared by the package.'),
        renderRow('License File', dep.license.licenseFile || 'Unavailable', 'Path to the detected license file, when present.')
      ]);

      const vulnSection = renderSection('Vulnerabilities', 'Known vulnerabilities from npm audit results.', vulnTable);

      const maintenanceSection = renderSection(
        'Maintenance',
        'Recency of package publication based on maintenance checks.',
        '<p>Status: ' + dep.maintenance.status + (dep.maintenance.lastPublished ? ' · Last published: ' + dep.maintenance.lastPublished : '') + ' (' + (dep.maintenance.reason || '') + ')</p>'
      );

      const usageSection = renderSection('Usage', 'Usage signals from depcheck results.', '<p>' + dep.usage.status + ' — ' + dep.usage.reason + '</p>');

      const identitySection = renderKvSection('Identity & Metadata', 'Basic package metadata discovered locally.', [
        renderRow('Deprecated', yesNo(dep.identity.deprecated), 'This package has been marked as deprecated by its author.'),
        renderRow('Node Version Requirement', dep.identity.nodeEngine || 'None', 'Declared Node.js versions this package claims to support.'),
        renderRow('Repository Linked', yesNo(dep.identity.hasRepository), 'Indicates whether the package declares a source repository.'),
        renderRow('Funding Info', yesNo(dep.identity.hasFunding), 'Indicates whether the package declares funding or sponsorship information.')
      ]);

      const dependencySurfaceSection = renderKvSection('Dependency Surface Area', 'Declared dependency counts and coupling indicators.', [
        renderRow(
          'Dependency Surface',
          dep.dependencySurface.dependencies + ' prod / ' +
            dep.dependencySurface.devDependencies + ' dev / ' +
            dep.dependencySurface.peerDependencies + ' peer / ' +
            dep.dependencySurface.optionalDependencies + ' optional',
          'Number of dependencies this package declares.'
        ),
        renderRow('Peer Dependencies', yesNo(dep.dependencySurface.hasPeerDependencies), 'Peer dependencies increase coupling and can complicate upgrades.')
      ]);

      const sizeSection = renderKvSection('Size & Footprint', 'Local install size and file count.', [
        renderRow('Installed Size', formatBytes(dep.sizeFootprint.installedSize), 'Disk space consumed by this package and its files.'),
        renderRow('File Count', String(dep.sizeFootprint.fileCount), 'Total number of files installed for this package.')
      ]);

      const buildSection = renderKvSection('Build & Platform Complexity', 'Signals that may require native builds or install-time scripts.', [
        renderRow('Native Code', yesNo(dep.buildPlatform.nativeBindings), 'Package includes native code that may require compilation.'),
        renderRow('Install Scripts', yesNo(dep.buildPlatform.installScripts), 'Package executes code during installation.')
      ]);

      const moduleSection = renderKvSection('Module System', 'Module format indicators derived from package metadata.', [
        renderRow('Module Format', dep.moduleSystem.format, 'Indicates whether the package uses CommonJS, ES Modules, or both.'),
        renderRow('Conditional Exports', yesNo(dep.moduleSystem.conditionalExports), 'Package defines conditional export paths for different environments.')
      ]);

      const typesSection = renderKvSection('TypeScript Support', 'Whether the package ships bundled type definitions.', [
        renderRow('TypeScript Types', dep.typescript.types === 'bundled' ? 'Bundled' : 'None', 'Indicates whether the package ships TypeScript type definitions.')
      ]);

      const graphSection = renderKvSection('Graph Shape', 'Derived connectivity within the dependency graph.', [
        renderRow('Depended On By', String(dep.graph.fanIn), 'Number of other dependencies that rely on this package.'),
        renderRow('Depends On', String(dep.graph.fanOut), 'Number of dependencies this package relies on.')
      ]);

      return [
        '<details>',
        summary,
        overviewSection,
        licenseSection,
        vulnSection,
        maintenanceSection,
        usageSection,
        identitySection,
        dependencySurfaceSection,
        sizeSection,
        buildSection,
        moduleSection,
        typesSection,
        graphSection,
        '<details class="section"><summary>Raw data</summary><pre>' + rawJson + '</pre></details>',
        '</details>'
      ].join('');
    }

    function renderList() {
      const deps = sortDeps(applyFilters());
      container.innerHTML = deps.map(renderDep).join('');
    }

    Object.values(controls).forEach((ctrl) => {
      if (!ctrl) return;
      ctrl.addEventListener('input', renderList);
      ctrl.addEventListener('change', renderList);
    });

    renderList();
  </script>
</body>
</html>`;
}
function renderToolErrors(data) {
    const entries = Object.entries(data.toolErrors || {});
    if (!entries.length)
        return '';
    const list = entries.map(([tool, err]) => `<div><strong>${tool}:</strong> ${err}</div>`).join('');
    return `<div class="tool-errors"><strong>Some tools failed:</strong>${list}</div>`;
}
