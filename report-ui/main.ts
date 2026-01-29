/**
 * Dependency Radar Report - Client-side rendering
 * TypeScript version of the report rendering logic
 */

import './style.css';
import type { AggregatedData, DependencyRecord, ExecutionSignal, Severity } from './types';

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

const EXECUTION_SIGNAL_LABELS: Record<ExecutionSignal, string> = {
  'network-access': 'Accesses the network during install',
  'dynamic-exec': 'Uses dynamic code execution',
  'child-process': 'Spawns child processes',
  'encoding': 'Encodes or decodes data',
  'obfuscated': 'Install-time code is obfuscated or minified',
  'reads-env': 'Reads environment variables',
  'reads-home': 'Accesses the user home directory',
  'uses-ssh': 'Accesses SSH or credential-related paths'
};

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
  return dep.security?.vulnerabilities?.highest || 'none';
}

function yesNo(flag: boolean | undefined): string {
  return flag ? 'Yes' : 'No';
}

function escapeHtml(str: string | null | undefined): string {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function getHighestRisk(dep: DependencyRecord): 'red' | 'amber' | 'green' {
  const risks = [dep.security.vulnRisk, dep.compliance.licenseRisk];
  if (risks.includes('red')) return 'red';
  if (risks.includes('amber')) return 'amber';
  return 'green';
}

function scopeLabel(scope: string): string {
  if (scope === 'runtime') return 'Runtime';
  if (scope === 'dev') return 'Dev';
  if (scope === 'optional') return 'Optional';
  if (scope === 'peer') return 'Peer';
  return scope;
}

function capitalize(str: string): string {
  if (!str) return str;
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function badgeCard(label: string, value: string, tone: string): string {
  return '<div class="badge-card ' + tone + '">' +
    '<span class="badge-label">' + escapeHtml(label) + '</span>' +
    '<span class="badge-value">' + escapeHtml(value) + '</span>' +
    '</div>';
}

function renderKvItem(label: string, value: string | number, hint?: string): string {
  let html = '<div class="kv-item">';
  html += '<span class="kv-label">' + escapeHtml(label) + '</span>';
  html += '<span class="kv-value">' + escapeHtml(String(value)) + '</span>';
  if (hint) html += '<span class="kv-hint">' + escapeHtml(hint) + '</span>';
  html += '</div>';
  return html;
}

function renderKvItemHtml(label: string, valueHtml: string, hint?: string): string {
  let html = '<div class="kv-item">';
  html += '<span class="kv-label">' + escapeHtml(label) + '</span>';
  html += valueHtml;
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

function executionRiskTone(execution: DependencyRecord['execution'] | undefined): 'green' | 'amber' | 'red' {
  return execution?.risk ?? 'green';
}

function executionRiskLabel(execution: DependencyRecord['execution'] | undefined): string {
  const tone = executionRiskTone(execution);
  if (tone === 'red') return 'High';
  if (tone === 'amber') return 'Medium';
  return 'Low';
}

function renderExecutionSection(execution: NonNullable<DependencyRecord['execution']>): string {
  const items: string[] = [
    renderKvItem('Risk', executionRiskLabel(execution), 'Install-time behaviour worth reviewing')
  ];

  if (execution.native) {
    items.push(renderKvItem('Native Code', 'Yes', 'Requires native build tooling or binaries'));
  }

  if (execution.scripts?.hooks?.length) {
    items.push(renderKvItemHtml(
      'Lifecycle Hooks',
      renderPackageList(execution.scripts.hooks, 6),
      'Install-time hooks from package.json'
    ));
  }

  if (typeof execution.scripts?.complexity === 'number') {
    items.push(renderKvItem('Complexity', execution.scripts.complexity, 'Heuristic score from lifecycle scripts'));
  }

  if (execution.scripts?.signals?.length) {
    const labels = execution.scripts.signals.map((signal) => EXECUTION_SIGNAL_LABELS[signal]);
    items.push(renderKvItemHtml(
      'Signals',
      renderPackageList(labels, 6),
      'Review-worthy install-time behaviour flags'
    ));
  }

  return renderSection(
    'Suspicious / Install-time behaviour',
    'Install-time signals surfaced for review',
    '<div class="kv-grid">' + items.join('') + '</div>'
  );
}

function renderPackageLinks(links: DependencyRecord['package']['links']): string {
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
  const licenseText = dep.compliance.license || 'Unknown';
  const licenseCategory = getLicenseCategory(licenseText);
  const highestRisk = getHighestRisk(dep);
  const severity = highestSeverity(dep);

  const licenseCategoryDisplay: Record<LicenseCategory, { text: string; class: string }> = {
    permissive: { text: 'Permissive', class: 'green' },
    weakCopyleft: { text: 'Weak Copyleft', class: 'amber' },
    strongCopyleft: { text: 'Strong Copyleft', class: 'red' },
    unknown: { text: 'Unknown', class: 'gray' }
  };

  const depTypeText = dep.usage.direct ? 'Dependency' : 'Sub-Dependency';
  const depTypeClass = dep.usage.direct ? 'green' : 'amber';
  const scopeTone = dep.usage.scope === 'runtime' ? 'green' : dep.usage.scope === 'dev' ? 'amber' : dep.usage.scope === 'optional' ? 'amber' : 'gray';
  const executionTone = executionRiskTone(dep.execution);
  const executionLabel = executionRiskLabel(dep.execution);

  const badges = [
    badgeCard('Type', depTypeText, depTypeClass),
    badgeCard('Scope', scopeLabel(dep.usage.scope), scopeTone),
    badgeCard('License', licenseText, licenseCategoryDisplay[licenseCategory].class),
    badgeCard('Vulns', capitalize(severity), dep.security.vulnRisk),
    badgeCard('Install', executionLabel, executionTone)
  ];

  const summary = [
    '<summary class="dep-summary">',
      '<svg class="expand-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m9 18 6-6-6-6"/></svg>',
      '<span class="dep-name">' + escapeHtml(dep.package.name) + '<span class="dep-version">@' + escapeHtml(dep.package.version) + '</span></span>',
      '<div class="dep-indicators">',
        badges.join(''),
      '</div>',
    '</summary>'
  ].join('');

  const rawJson = JSON.stringify(dep, null, 2);

  const originsItems = [
    '<div class="kv-item"><span class="kv-label">Root Packages</span><span class="kv-value">' + dep.usage.origins.rootPackageCount + '</span></div>',
    '<div class="kv-item"><span class="kv-label">Top Root Packages</span>' + renderPackageList(dep.usage.origins.topRootPackages, 8) + '</div>'
  ];
  if (dep.usage.origins.workspaces && dep.usage.origins.workspaces.length > 0) {
    originsItems.push('<div class="kv-item"><span class="kv-label">Workspaces</span>' + renderPackageList(dep.usage.origins.workspaces, 8) + '</div>');
  }

  const overviewSection = renderKvSection('Overview', 'Dependency position and scope', [
    renderKvItem('Type', depTypeText, dep.usage.direct ? 'Listed in package.json' : 'Installed as a sub-dependency'),
    renderKvItem('Scope', scopeLabel(dep.usage.scope), 'Scope inferred from root dependencies'),
    renderKvItem('Depth', dep.usage.depth, 'How deep this package is in the dependency tree')
  ]);

  const originsSection = renderSection('Origins', 'Direct roots for this dependency', '<div class="kv-grid">' + originsItems.join('') + '</div>');

  const licenseSection = renderKvSection('License', 'License information for this package', [
    renderKvItem('License', licenseText, 'The declared license'),
    renderKvItem('Category', licenseCategoryDisplay[licenseCategory].text, 'Business-friendliness classification')
  ]);

  const vulnSection = renderKvSection('Vulnerabilities', 'npm audit summary', [
    renderKvItem('Critical', dep.security.vulnerabilities.critical),
    renderKvItem('High', dep.security.vulnerabilities.high),
    renderKvItem('Moderate', dep.security.vulnerabilities.moderate),
    renderKvItem('Low', dep.security.vulnerabilities.low),
    renderKvItem('Highest', capitalize(dep.security.vulnerabilities.highest))
  ]);

  const identitySection = renderKvSection('Identity', 'Package metadata', [
    renderKvItem('Deprecated', yesNo(dep.package.deprecated), 'Whether the author has deprecated this package'),
    renderKvItem('Node Engine', dep.upgrade.nodeEngine || 'Any', 'Required Node.js version')
  ]);

  const dependencySurfaceSection = renderKvSection('Dependency Surface', 'What this package depends on', [
    renderKvItem('Dependencies', dep.graph.dependencySurface.deps + ' prod / ' + dep.graph.dependencySurface.dev + ' dev / ' + dep.graph.dependencySurface.peer + ' peer / ' + dep.graph.dependencySurface.opt + ' optional', '')
  ]);

  const installSection = dep.execution ? renderExecutionSection(dep.execution) : '';

  const typesSection = renderKvSection('TypeScript', 'Type definition support', [
    renderKvItem('Types', dep.usage.tsTypes === 'bundled' ? 'Bundled' : dep.usage.tsTypes === 'definitelyTyped' ? 'DefinitelyTyped' : dep.usage.tsTypes === 'none' ? 'None' : 'Unknown', 'Types availability')
  ]);

  const graphSection = renderKvSection('Graph', 'Dependency graph summary', [
    renderKvItem('Fan In', dep.graph.fanIn),
    renderKvItem('Fan Out', dep.graph.fanOut)
  ]);

  return [
    '<details class="dep-card" data-risk="' + highestRisk + '">',
    summary,
    '<div class="dep-details">',
    renderPackageLinks(dep.package.links),
    overviewSection,
    originsSection,
    licenseSection,
    vulnSection,
    identitySection,
    dependencySurfaceSection,
    installSection,
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
  
  // Update header info with new chip-based layout
  const projectPathEl = document.getElementById('project-path');
  if (projectPathEl) projectPathEl.textContent = report.project.projectDir;
  
  // Git branch chip
  const gitBranchItem = document.getElementById('git-branch-item');
  const gitBranchEl = document.getElementById('git-branch');
  if (report.git?.branch && report.git.branch && gitBranchItem && gitBranchEl) {
    gitBranchEl.textContent = report.git.branch;
    gitBranchItem.style.display = '';
  }
  
  // Node version chip
  const nodeItem = document.getElementById('node-item');
  const nodeVersionEl = document.getElementById('node-version');
  const nodeDisclaimer = document.getElementById('node-disclaimer');
  if (report.environment && nodeItem && nodeVersionEl) {
    const runtimeVersion = report.environment.runtimeVersion?.replace(/^v/, '') || 'unknown';
    const minRequiredMajor = report.environment.minRequiredMajor;
    nodeVersionEl.textContent = runtimeVersion + (minRequiredMajor && minRequiredMajor > 0 ? ` (requires ≥${minRequiredMajor})` : '');
    nodeItem.style.display = '';
    if (minRequiredMajor && minRequiredMajor > 0 && nodeDisclaimer) {
      nodeDisclaimer.textContent = 'Node requirement derived from dependency engine ranges.';
      nodeDisclaimer.style.display = '';
    }
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
  
  // Controls
  const controls = {
    search: document.getElementById('search') as HTMLInputElement,
    direct: document.getElementById('direct-filter') as HTMLSelectElement,
    runtime: document.getElementById('runtime-filter') as HTMLSelectElement,
    sort: document.getElementById('sort-by') as HTMLSelectElement,
    sortDirection: document.getElementById('sort-direction') as HTMLButtonElement,
    hasVulns: document.getElementById('has-vulns') as HTMLInputElement,
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
  
  const allDependencies = Object.values(report.dependencies || {});

  function applyFilters(): DependencyRecord[] {
    const term = (controls.search.value || '').toLowerCase();
    const directFilter = controls.direct.value;
    const runtimeFilter = controls.runtime.value;
    const hasVulns = controls.hasVulns.checked;
    
    const showPermissive = controls.licensePermissive.checked;
    const showWeakCopyleft = controls.licenseWeakCopyleft.checked;
    const showStrongCopyleft = controls.licenseStrongCopyleft.checked;
    const showUnknown = controls.licenseUnknown.checked;
    
    return allDependencies.filter((dep) => {
      if (term && !(dep.package.name.toLowerCase().includes(term) || dep.compliance.license.toLowerCase().includes(term))) return false;
      if (directFilter === 'direct' && !dep.usage.direct) return false;
      if (directFilter === 'transitive' && dep.usage.direct) return false;
      if (runtimeFilter !== 'all' && dep.usage.scope !== runtimeFilter) return false;
      if (hasVulns && severityOrder[highestSeverity(dep)] === 0) return false;
      
      const licenseCategory = getLicenseCategory(dep.compliance.license);
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
      sorted.sort((a, b) => a.package.name.localeCompare(b.package.name));
    } else if (sortBy === 'depth') {
      sorted.sort((a, b) => a.usage.depth - b.usage.depth);
    } else if (sortBy === 'severity') {
      sorted.sort((a, b) => severityOrder[highestSeverity(b)] - severityOrder[highestSeverity(a)]);
    }
    
    if (!sortAscending) sorted.reverse();
    return sorted;
  }
  
  function renderList(): void {
    const filtered = applyFilters();
    const deps = sortDeps(filtered);
    
    const totalCount = report.summary?.dependencyCount || allDependencies.length;
    summaryEl.innerHTML = 'Showing <strong>' + deps.length + '</strong> of <strong>' + totalCount + '</strong> dependencies';
    
    if (deps.length === 0) {
      container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">📦</div><div class="empty-state-text">No dependencies match your filters</div></div>';
      return;
    }
    
    container.innerHTML = deps.map(renderDep).join('');
  }
  
  // Event listeners
  const filterControls = [
    controls.search, controls.direct, controls.runtime, controls.sort, controls.hasVulns,
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
