/**
 * Dependency Radar Report - Client-side rendering
 * TypeScript version of the report rendering logic
 */

import './style.css';
import type { AggregatedData, DependencyRecord, Severity } from './types';

// In development, load sample data; in production, data is embedded
async function loadReportData(): Promise<AggregatedData> {
  const dataEl = document.getElementById('radar-data');
  if (dataEl && dataEl.textContent && dataEl.textContent.trim() !== '{}') {
    return JSON.parse(dataEl.textContent);
  }
  // Development mode: fetch sample data
  const response = await fetch('./sample-data.json');
  return response.json();
}

// License categorization
const LICENSE_CATEGORIES = {
  permissive: ['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', 'Unlicense', '0BSD', 'CC0-1.0', 'BSD', 'Apache', 'Apache 2.0', 'Apache License 2.0', 'MIT License', 'ISC License'],
  weakCopyleft: ['LGPL-2.1', 'LGPL-3.0', 'LGPL-2.0', 'LGPL', 'MPL-2.0', 'MPL-1.1', 'MPL', 'EPL-1.0', 'EPL-2.0', 'EPL'],
  strongCopyleft: ['GPL-2.0', 'GPL-3.0', 'GPL', 'AGPL-3.0', 'AGPL', 'GPL-2.0-only', 'GPL-3.0-only', 'GPL-2.0-or-later', 'GPL-3.0-or-later']
} as const;

type LicenseCategory = 'permissive' | 'weakCopyleft' | 'strongCopyleft' | 'unknown';

function getLicenseCategory(license: string | undefined | null): LicenseCategory {
  if (!license) return 'unknown';
  const normalized = license.toUpperCase();
  for (const [cat, licenses] of Object.entries(LICENSE_CATEGORIES)) {
    if (licenses.some(l => normalized.includes(l.toUpperCase()))) return cat as LicenseCategory;
  }
  return 'unknown';
}

const severityOrder: Record<Severity | 'none', number> = { none: 0, low: 1, moderate: 2, high: 3, critical: 4 };

function highestSeverity(dep: DependencyRecord): Severity | 'none' {
  return dep.vulnerabilities?.highestSeverity || 'none';
}

function formatBytes(bytes: number | undefined): string {
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

function yesNo(flag: boolean | undefined): string {
  return flag ? 'Yes' : 'No';
}

function escapeHtml(str: string | null | undefined): string {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function getHighestRisk(dep: DependencyRecord): 'red' | 'amber' | 'green' {
  const risks = [dep.vulnRisk, dep.licenseRisk];
  if (risks.includes('red')) return 'red';
  if (risks.includes('amber')) return 'amber';
  return 'green';
}

function usageLabel(status: string): string {
  if (status === 'imported') return 'Imported';
  if (status === 'not-imported') return 'Not statically imported';
  if (status === 'undeclared') return 'Imported but not declared';
  return 'Unknown';
}

function indicator(text: string, tone: string): string {
  return '<div class="indicator"><span class="indicator-dot ' + tone + '"></span>' + escapeHtml(text) + '</div>';
}

function indicatorSeparator(): string {
  return '<div class="indicator-separator"></div>';
}

function renderKvItem(label: string, value: string | number, hint?: string): string {
  let html = '<div class="kv-item">';
  html += '<span class="kv-label">' + escapeHtml(label) + '</span>';
  html += '<span class="kv-value">' + escapeHtml(String(value)) + '</span>';
  if (hint) html += '<span class="kv-hint">' + escapeHtml(hint) + '</span>';
  html += '</div>';
  return html;
}

function renderPackageList(packages: string[] | undefined, maxShow: number): string {
  if (!packages || packages.length === 0) return '<span class="kv-value">None</span>';
  const shown = packages.slice(0, maxShow);
  const remaining = packages.length - maxShow;
  let html = '<div class="package-list">';
  shown.forEach(pkg => {
    html += '<span class="package-tag">' + escapeHtml(pkg) + '</span>';
  });
  if (remaining > 0) {
    html += '<span class="package-tag">+' + remaining + ' more</span>';
  }
  html += '</div>';
  return html;
}

function renderSection(title: string, desc: string | undefined, bodyHtml: string): string {
  let html = '<div class="section">';
  html += '<div class="section-header">';
  html += '<span class="section-title">' + escapeHtml(title) + '</span>';
  if (desc) html += '<span class="section-desc">' + escapeHtml(desc) + '</span>';
  html += '</div>';
  html += bodyHtml;
  html += '</div>';
  return html;
}

function renderKvSection(title: string, desc: string | undefined, items: string[]): string {
  return renderSection(title, desc, '<div class="kv-grid">' + items.join('') + '</div>');
}

function renderPackageLinks(links: DependencyRecord['links']): string {
  const icons = {
    npm: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M0 7.334v8h6.666v1.332H12v-1.332h12v-8H0zm6.666 6.664H5.334v-4H3.999v4H1.335V8.667h5.331v5.331zm4 0v1.336H8.001V8.667h5.334v5.332h-2.669v-.001zm12.001 0h-1.33v-4h-1.336v4h-1.335v-4h-1.33v4h-2.671V8.667h8.002v5.331zM10.665 10H12v2.667h-1.335V10z"/></svg>',
    repo: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>',
    bugs: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    homepage: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>'
  };
  
  let html = '<div class="package-links">';
  html += '<a href="' + escapeHtml(links.npm) + '" target="_blank" rel="noopener" class="package-link">' + icons.npm + 'npm</a>';
  
  if (links.repository) {
    html += '<a href="' + escapeHtml(links.repository) + '" target="_blank" rel="noopener" class="package-link">' + icons.repo + 'Repository</a>';
  }
  
  if (links.homepage) {
    html += '<a href="' + escapeHtml(links.homepage) + '" target="_blank" rel="noopener" class="package-link">' + icons.homepage + 'Homepage</a>';
  }
  
  if (links.bugs) {
    html += '<a href="' + escapeHtml(links.bugs) + '" target="_blank" rel="noopener" class="package-link">' + icons.bugs + 'Issues</a>';
  }
  
  html += '</div>';
  return html;
}

function renderDep(dep: DependencyRecord): string {
  const licenseText = dep.license.license || 'Unknown';
  const licenseCategory = getLicenseCategory(licenseText);
  const highestRisk = getHighestRisk(dep);
  const severity = highestSeverity(dep);
  
  const licenseCategoryDisplay: Record<LicenseCategory, { text: string; class: string }> = {
    permissive: { text: 'Permissive', class: 'green' },
    weakCopyleft: { text: 'Weak Copyleft', class: 'amber' },
    strongCopyleft: { text: 'Strong Copyleft', class: 'red' },
    unknown: { text: 'Unknown', class: 'gray' }
  };
  
  const depTypeText = dep.direct ? 'Dependency' : 'Sub-Dependency';
  const depTypeClass = dep.direct ? 'green' : 'amber';
  
  const indicators = [
    indicator(depTypeText, depTypeClass),
    indicatorSeparator(),
    indicator(dep.runtimeClass, dep.runtimeClass === 'runtime' ? 'green' : dep.runtimeClass === 'build-time' ? 'amber' : 'gray'),
    indicatorSeparator(),
    indicator(licenseText + ' (' + licenseCategoryDisplay[licenseCategory].text + ')', licenseCategoryDisplay[licenseCategory].class),
    indicatorSeparator(),
    indicator('Vulns: ' + severity, dep.vulnRisk),
    indicatorSeparator(),
    indicator(
      usageLabel(dep.usage.status),
      dep.usage.status === 'undeclared'
        ? 'red'
        : dep.usage.status === 'imported'
          ? 'green'
          : dep.usage.status === 'not-imported'
            ? 'amber'
            : 'gray'
    )
  ];
  
  const summary = [
    '<summary class="dep-summary">',
      '<svg class="expand-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 18 6-6-6-6"/></svg>',
      '<span class="dep-name">' + escapeHtml(dep.name) + '<span class="dep-version">@' + escapeHtml(dep.version) + '</span></span>',
      '<div class="dep-indicators">',
        indicators.join(''),
      '</div>',
    '</summary>'
  ].join('');
  
  const vulnRows = dep.vulnerabilities.items.map((v) => 
    '<tr data-severity="' + v.severity + '"><td>' + escapeHtml(v.title) + '</td><td>' + escapeHtml(v.severity) + '</td><td>' + escapeHtml(v.vulnerableRange || '') + '</td><td><a href="' + escapeHtml(v.url || '#') + '" target="_blank" rel="noopener">Link</a></td></tr>'
  ).join('');
  
  const vulnTable = dep.vulnerabilities.items.length 
    ? '<table class="vuln-table"><thead><tr><th>Title</th><th>Severity</th><th>Range</th><th>Ref</th></tr></thead><tbody>' + vulnRows + '</tbody></table>' 
    : '<p class="no-vulns">No known vulnerabilities.</p>';
  
  const rawJson = JSON.stringify(dep, null, 2);
  
  const parentNames = (dep.parents || []).map(key => key.split('@')[0]);
  const installedBy = (dep.rootCauses || []).join(', ') || (dep.direct ? 'package.json' : 'Unknown');
  
  const overviewSection = renderKvSection('Overview', 'Dependency position and runtime classification', [
    renderKvItem('Type', depTypeText, dep.direct ? 'Listed in package.json' : 'Installed as a sub-dependency'),
    renderKvItem('Depth', dep.depth, 'How deep this package is in the dependency tree'),
    renderKvItem('Parents', parentNames.join(', ') || 'None (direct dependency)', 'Packages that directly depend on this'),
    renderKvItem('Installed By', installedBy, 'Root dependency in package.json that causes this to be installed'),
    renderKvItem('Runtime Class', dep.runtimeClass, dep.runtimeReason)
  ]);
  
  const licenseSection = renderKvSection('License', 'License information for this package', [
    renderKvItem('License', licenseText, 'The declared license'),
    renderKvItem('Category', licenseCategoryDisplay[licenseCategory].text, 'Business-friendliness classification'),
    renderKvItem('License File', dep.license.licenseFile || 'Not found', 'Path to license file if present')
  ]);
  
  const vulnSection = renderSection('Vulnerabilities', 'Known security issues from npm audit', vulnTable);
  
  const maintenanceSection = renderSection(
    'Maintenance',
    'Package maintenance status',
    '<div class="kv-grid">' +
      renderKvItem('Status', dep.maintenance.status, dep.maintenance.reason) +
      (dep.maintenance.lastPublished ? renderKvItem('Last Published', dep.maintenance.lastPublished, '') : '') +
    '</div>'
  );
  
  const usageSection = renderSection(
    'Usage',
    'Static import usage in your codebase',
    '<div class="kv-grid">' + renderKvItem('Status', usageLabel(dep.usage.status), dep.usage.reason) + '</div>'
  );
  
  const identitySection = renderKvSection('Identity & Metadata', 'Package metadata', [
    renderKvItem('Deprecated', yesNo(dep.identity.deprecated), 'Whether the author has deprecated this package'),
    renderKvItem('Node Engine', dep.identity.nodeEngine || 'Any', 'Required Node.js version'),
    renderKvItem('Repository', yesNo(dep.identity.hasRepository), 'Whether source repo is linked'),
    renderKvItem('Funding', yesNo(dep.identity.hasFunding), 'Whether funding info is provided')
  ]);
  
  const dependencySurfaceSection = renderKvSection('Dependency Surface', 'What this package depends on', [
    renderKvItem('Dependencies', dep.dependencySurface.dependencies + ' prod / ' + dep.dependencySurface.devDependencies + ' dev / ' + dep.dependencySurface.peerDependencies + ' peer / ' + dep.dependencySurface.optionalDependencies + ' optional', ''),
    renderKvItem('Has Peer Dependencies', yesNo(dep.dependencySurface.hasPeerDependencies), 'Peer deps can complicate upgrades')
  ]);
  
  const sizeSection = renderKvSection('Size & Footprint', 'Disk space usage', [
    renderKvItem('Installed Size', formatBytes(dep.sizeFootprint.installedSize), 'Total size on disk'),
    renderKvItem('File Count', dep.sizeFootprint.fileCount, 'Number of files installed')
  ]);
  
  const buildSection = renderKvSection('Build & Platform', 'Build complexity indicators', [
    renderKvItem('Native Code', yesNo(dep.buildPlatform.nativeBindings), 'Requires compilation'),
    renderKvItem('Install Scripts', yesNo(dep.buildPlatform.installScripts), 'Runs code during install')
  ]);
  
  const moduleSection = renderKvSection('Module System', 'Module format information', [
    renderKvItem('Format', dep.moduleSystem.format, 'CommonJS, ESM, or dual'),
    renderKvItem('Conditional Exports', yesNo(dep.moduleSystem.conditionalExports), 'Uses exports field')
  ]);
  
  const typesSection = renderKvSection('TypeScript', 'Type definition support', [
    renderKvItem('Types', dep.typescript.types === 'bundled' ? 'Bundled' : 'None', 'Whether types are included')
  ]);
  
  const dependedOnByList = dep.graph?.dependedOnBy || [];
  const dependsOnList = dep.graph?.dependsOn || [];
  
  const graphSection = renderSection('Graph Shape', 'Dependency graph connections', 
    '<div class="kv-grid">' +
      '<div class="kv-item"><span class="kv-label">Depended On By (' + dep.graph.fanIn + ')</span>' + renderPackageList(dependedOnByList, 8) + '</div>' +
      '<div class="kv-item"><span class="kv-label">Depends On (' + dep.graph.fanOut + ')</span>' + renderPackageList(dependsOnList, 8) + '</div>' +
    '</div>'
  );
  
  return [
    '<details class="dep-card" data-risk="' + highestRisk + '">',
    summary,
    '<div class="dep-details">',
    renderPackageLinks(dep.links),
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
    '<details class="raw-data-toggle"><summary>View raw data</summary><pre>' + escapeHtml(rawJson) + '</pre></details>',
    '</div>',
    '</details>'
  ].join('');
}

// Main application
async function init(): Promise<void> {
  const report = await loadReportData();
  const container = document.getElementById('dependency-list')!;
  const summaryEl = document.getElementById('results-summary')!;
  
  // Update header info
  const projectPathEl = document.getElementById('project-path');
  if (projectPathEl) projectPathEl.textContent = report.projectPath;
  
  const gitBranchBr = document.getElementById('git-branch-br');
  const gitBranchText = document.getElementById('git-branch-text');
  if (report.gitBranch && gitBranchText) {
    gitBranchText.innerHTML = 'Branch: <strong>' + escapeHtml(report.gitBranch) + '</strong>';
  } else if (gitBranchBr) {
    gitBranchBr.remove();
  }
  
  const nodeBlockEl = document.getElementById('node-block');
  if (nodeBlockEl && report.environment?.node) {
    const runtimeVersion = report.environment.node.runtimeVersion?.replace(/^v/, '') || 'unknown';
    const minRequiredMajor = report.environment.node.minRequiredMajor;
    const nodeRequirement = minRequiredMajor !== undefined ? ` · dependency engines require ≥${minRequiredMajor}` : '';
    nodeBlockEl.innerHTML = minRequiredMajor !== undefined
      ? `<br/>Node: run on ${escapeHtml(runtimeVersion)}${nodeRequirement}<br/><span class="header-disclaimer">Derived from declared dependency engine ranges; does not guarantee runtime compatibility.</span>`
      : `<br/>Node: run on ${escapeHtml(runtimeVersion)}`;
  }
  
  // Format timestamp
  const dateEl = document.getElementById('formatted-date');
  if (dateEl && report.generatedAt) {
    try {
      const date = new Date(report.generatedAt);
      const formatted = new Intl.DateTimeFormat(undefined, {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      }).format(date);
      dateEl.textContent = formatted;
    } catch {
      dateEl.textContent = report.generatedAt;
    }
  }
  
  // Render tool errors
  const toolErrorsEl = document.getElementById('tool-errors');
  if (toolErrorsEl && report.toolErrors && Object.keys(report.toolErrors).length > 0) {
    const errorList = Object.entries(report.toolErrors)
      .map(([tool, err]) => `<div><strong>${escapeHtml(tool)}:</strong> ${escapeHtml(err)}</div>`)
      .join('');
    toolErrorsEl.innerHTML = `<strong>Some tools failed:</strong>${errorList}`;
  }
  
  // Controls
  const controls = {
    search: document.getElementById('search') as HTMLInputElement,
    direct: document.getElementById('direct-filter') as HTMLSelectElement,
    runtime: document.getElementById('runtime-filter') as HTMLSelectElement,
    sort: document.getElementById('sort-by') as HTMLSelectElement,
    sortDirection: document.getElementById('sort-direction') as HTMLButtonElement,
    hasVulns: document.getElementById('has-vulns') as HTMLInputElement,
    unusedOnly: document.getElementById('unused-only') as HTMLInputElement,
    themeSwitch: document.getElementById('theme-switch') as HTMLElement,
    licenseToggle: document.getElementById('license-toggle') as HTMLButtonElement,
    licensePanel: document.getElementById('license-panel') as HTMLElement,
    licensePermissive: document.getElementById('license-permissive') as HTMLInputElement,
    licenseWeakCopyleft: document.getElementById('license-weak-copyleft') as HTMLInputElement,
    licenseStrongCopyleft: document.getElementById('license-strong-copyleft') as HTMLInputElement,
    licenseUnknown: document.getElementById('license-unknown') as HTMLInputElement,
    licenseAll: document.getElementById('license-all') as HTMLButtonElement,
    licenseFriendly: document.getElementById('license-friendly') as HTMLButtonElement
  };
  
  let sortAscending = true;
  
  // Theme handling
  const savedTheme = localStorage.getItem('dependency-radar-theme');
  if (savedTheme === 'light') {
    document.documentElement.classList.add('light');
    controls.themeSwitch.classList.add('light');
  }
  
  controls.themeSwitch.addEventListener('click', () => {
    document.documentElement.classList.toggle('light');
    controls.themeSwitch.classList.toggle('light');
    const isLight = document.documentElement.classList.contains('light');
    localStorage.setItem('dependency-radar-theme', isLight ? 'light' : 'dark');
  });
  
  // License panel toggle
  controls.licenseToggle.addEventListener('click', () => {
    controls.licenseToggle.classList.toggle('open');
    controls.licensePanel.classList.toggle('open');
  });
  
  // Sort direction toggle
  controls.sortDirection.addEventListener('click', () => {
    sortAscending = !sortAscending;
    controls.sortDirection.textContent = sortAscending ? '↑' : '↓';
    renderList();
  });
  
  // License quick actions
  controls.licenseAll.addEventListener('click', () => {
    controls.licensePermissive.checked = true;
    controls.licenseWeakCopyleft.checked = true;
    controls.licenseStrongCopyleft.checked = true;
    controls.licenseUnknown.checked = true;
    renderList();
  });
  
  controls.licenseFriendly.addEventListener('click', () => {
    controls.licensePermissive.checked = true;
    controls.licenseWeakCopyleft.checked = false;
    controls.licenseStrongCopyleft.checked = false;
    controls.licenseUnknown.checked = false;
    renderList();
  });
  
  function applyFilters(): DependencyRecord[] {
    const term = (controls.search.value || '').toLowerCase();
    const directFilter = controls.direct.value;
    const runtimeFilter = controls.runtime.value;
    const hasVulns = controls.hasVulns.checked;
    const notImportedOnly = controls.unusedOnly.checked;
    
    const showPermissive = controls.licensePermissive.checked;
    const showWeakCopyleft = controls.licenseWeakCopyleft.checked;
    const showStrongCopyleft = controls.licenseStrongCopyleft.checked;
    const showUnknown = controls.licenseUnknown.checked;
    
    return report.dependencies.filter((dep) => {
      if (term && !(dep.name.toLowerCase().includes(term) || (dep.license.license || '').toLowerCase().includes(term))) return false;
      if (directFilter === 'direct' && !dep.direct) return false;
      if (directFilter === 'transitive' && dep.direct) return false;
      if (runtimeFilter !== 'all' && dep.runtimeClass !== runtimeFilter) return false;
      if (hasVulns && severityOrder[highestSeverity(dep)] === 0) return false;
      if (notImportedOnly && dep.usage.status !== 'not-imported') return false;
      
      const licenseCategory = getLicenseCategory(dep.license.license);
      if (licenseCategory === 'permissive' && !showPermissive) return false;
      if (licenseCategory === 'weakCopyleft' && !showWeakCopyleft) return false;
      if (licenseCategory === 'strongCopyleft' && !showStrongCopyleft) return false;
      if (licenseCategory === 'unknown' && !showUnknown) return false;
      
      return true;
    });
  }
  
  function sortDeps(deps: DependencyRecord[]): DependencyRecord[] {
    const sortBy = controls.sort.value;
    const sorted = [...deps];
    
    if (sortBy === 'name') {
      sorted.sort((a, b) => a.name.localeCompare(b.name));
    } else if (sortBy === 'depth') {
      sorted.sort((a, b) => a.depth - b.depth);
    } else if (sortBy === 'severity') {
      sorted.sort((a, b) => severityOrder[highestSeverity(b)] - severityOrder[highestSeverity(a)]);
    } else if (sortBy === 'size') {
      sorted.sort((a, b) => (b.sizeFootprint?.installedSize || 0) - (a.sizeFootprint?.installedSize || 0));
    }
    
    if (!sortAscending) sorted.reverse();
    return sorted;
  }
  
  function renderList(): void {
    const filtered = applyFilters();
    const deps = sortDeps(filtered);
    
    summaryEl.innerHTML = 'Showing <strong>' + deps.length + '</strong> of <strong>' + report.dependencies.length + '</strong> dependencies';
    
    if (deps.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📦</div><div class="empty-state-text">No dependencies match your filters</div></div>';
      return;
    }
    
    container.innerHTML = deps.map(renderDep).join('');
  }
  
  // Event listeners
  const filterControls = [
    controls.search, controls.direct, controls.runtime, controls.sort, controls.hasVulns, controls.unusedOnly,
    controls.licensePermissive, controls.licenseWeakCopyleft, controls.licenseStrongCopyleft, controls.licenseUnknown
  ];
  
  filterControls.forEach((ctrl) => {
    if (!ctrl) return;
    ctrl.addEventListener('input', renderList);
    ctrl.addEventListener('change', renderList);
  });
  
  renderList();
}

// Initialize on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
