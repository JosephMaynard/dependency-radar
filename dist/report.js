"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderReport = renderReport;
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const report_assets_1 = require("./report-assets");
async function renderReport(data, outputPath) {
    const html = buildHtml(data);
    await promises_1.default.mkdir(path_1.default.dirname(outputPath), { recursive: true });
    await promises_1.default.writeFile(outputPath, html, 'utf8');
}
function buildHtml(data) {
    var _a, _b, _c;
    const json = JSON.stringify(data).replace(/</g, '\\u003c');
    // Format the generated date
    let formattedDate = data.generatedAt;
    try {
        const date = new Date(data.generatedAt);
        formattedDate = new Intl.DateTimeFormat(undefined, {
            day: 'numeric',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        }).format(date);
    }
    catch {
        // Keep the original if parsing fails
    }
    // Build conditional meta items
    const runtimeVersion = ((_a = data.environment) === null || _a === void 0 ? void 0 : _a.runtimeVersion)
        ? data.environment.runtimeVersion.replace(/^v/, '')
        : null;
    const minRequiredMajor = (_b = data.environment) === null || _b === void 0 ? void 0 : _b.minRequiredMajor;
    const nodeVersionText = runtimeVersion
        ? `${runtimeVersion}${minRequiredMajor && minRequiredMajor > 0 ? ` (requires ≥${minRequiredMajor})` : ''}`
        : null;
    const nodeDisclaimer = minRequiredMajor && minRequiredMajor > 0
        ? 'Node requirement derived from dependency engine ranges.'
        : null;
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Dependency Radar</title>
  <style>
${report_assets_1.CSS_CONTENT}
  </style>
</head>
<body>
  <!-- Top Header (Scrollable) -->
  <header class="top-header">
    <div class="header-row">
      <div class="header-content">
        <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"
          viewBox="0 0 1024 1024" class="logo">
          <defs>
            <style>
              .st0, .st1 { fill: #ff8000; }
              .st2 { fill: #191772; }
              .st2, .st3, .st4, .st5 { stroke: #55fffa; stroke-miterlimit: 10; stroke-width: 6px; }
              .st6 { fill: #0a0a33; }
              .st7 { opacity: .3; }
              .st7, .st8 { fill: #55fffa; }
              .st3 { fill: #161466; }
              .st9 { fill: url(#linear-gradient); }
              .st10, .st1, .st11 { opacity: .4; }
              .st10, .st12 { fill: red; }
              .st4 { fill: #1c197f; }
              .st13, .st11 { fill: #00be00; }
              .st5 { fill: #141259; }
            </style>
            <linearGradient id="linear-gradient" x1="225" y1="287" x2="831.3" y2="287" gradientUnits="userSpaceOnUse">
              <stop offset=".4" stop-color="#55fffa" stop-opacity="0" />
              <stop offset="1" stop-color="#55fffa" stop-opacity=".5" />
            </linearGradient>
          </defs>
          <circle class="st6" cx="512" cy="512" r="512" />
          <circle class="st5" cx="512" cy="512" r="450" />
          <circle class="st3" cx="512" cy="512" r="325" />
          <circle class="st2" cx="512" cy="512" r="200" />
          <circle class="st4" cx="512" cy="512" r="80" />
          <path class="st9" d="M517.7,512l313.6-317.1c-81.5-82.1-194.5-132.9-319.3-132.9s-209.1,38.8-287,103.4l292.7,346.6Z" />
          <path class="st7" d="M891.9,618.4c-64.1,245.1-337.5,365.9-562.6,250.5,0,0-14.3-7.7-14.3-7.7-5.8-3.4-11.7-7.1-17.4-10.5-5.3-3.5-11.7-7.9-16.9-11.4-15-10.9-30.5-23.6-43.9-36.5-5.7-5.3-11.8-11.8-17.3-17.4-37-40.1-66.2-88-84.1-139.6-38.9-110.4-27.2-234.3,31.1-335.8,37.6-65.3,93.5-119.6,159.6-155.7,0,0,15-7.7,15-7.7,4.5-2.4,10.7-4.9,15.3-7.1,2.1-.9,5.6-2.6,7.7-3.4,3.9-1.5,11.8-4.7,15.7-6.2,4.7-1.8,11.1-3.8,15.9-5.4,0,0,4-1.3,4-1.3,6.7-1.8,13.5-4,20.3-5.7,116.4-29.7,241.1-7.4,339.7,61.6,18.6,13.1,36.2,27.6,52.6,43.4l-42.9,42.9c-17.1-17.4-35.9-33.2-55.9-47.1-4.7-2.9-13.9-9.3-18.6-11.7-3.1-1.8-8.1-4.7-11.1-6.4-4-2-10.7-5.5-14.7-7.6-5.1-2.4-11.6-5.3-16.7-7.6-5.7-2.3-11.4-4.5-17.1-6.8-60.2-21.9-126.3-27.5-189.3-16.1,0,0-14.6,2.9-14.6,2.9-6,1.4-12,3.1-18,4.5-5.5,1.7-12.3,3.7-17.8,5.5-4.4,1.5-11.4,4.1-15.8,5.7-3,1.2-9,3.7-12,5-43.3,18.6-83.4,46-116.3,79.8-105.7,106.7-134.5,269.3-74.7,406.7,49.8,114.5,155.4,198.1,278.4,219.7,94.7,17.4,195.6-3.1,276-56.1,76.9-50.4,135.7-128.5,160.8-217.2h0Z" />
          <path class="st7" d="M770.9,586c-20.5,84.7-85.9,156.4-167.8,185.8-103.6,37.8-221.1,7.9-294.5-74.2-73.1-80.1-91.2-199-47.6-298,28-63.9,80.3-116.6,144.1-144.9,91-41.1,199.6-30.9,281.6,26,13.1,9.1,25.5,19.2,37,30.2,0,0-42.9,42.9-42.9,42.9-21.5-22.4-47.3-40.6-75.7-53.1-18.3-7.8-37.9-13.6-57.6-16.7-38.4-6-78.3-2.5-115,10.4-34,11.7-65.3,31.6-90.7,57.1-89.3,88.8-94.6,233.1-14.3,329.6,37,45.2,90.4,76.8,147.9,87.3,130.1,24.7,258-55.6,295.4-182.4h0Z" />
          <path class="st7" d="M649.9,553.6c-13.4,61.2-70.2,107.5-133.1,109.4-48.9,2.2-96.8-21.6-125.4-61.3-75.1-106.5,4.4-248.5,133.3-247.2,40.8.5,80.9,16.7,110.7,44.7,0,0-42.9,42.9-42.9,42.9-11.9-13.1-27-23.5-43.8-29.5-28.9-10.5-62-8.3-89.4,5.9-61.5,31.6-81.6,109.8-45.9,168.4,17.8,29.7,48.4,51.3,82.3,58.2,66.3,14.4,134-26.8,154.1-91.6h0Z" />
          <rect class="st8" x="664.2" y="129.5" width="16.7" height="450" transform="translate(447.6 -371.7) rotate(45)" />
          <circle class="st8" cx="512" cy="512" r="32" />
          <circle class="st10" cx="800" cy="662" r="50" />
          <circle class="st12" cx="800" cy="662" r="25" />
          <circle class="st10" cx="256.9" cy="315.2" r="50" />
          <circle class="st12" cx="256.9" cy="315.2" r="25" />
          <circle class="st1" cx="400.1" cy="673" r="50" />
          <circle class="st0" cx="400.1" cy="673" r="25" />
          <circle class="st1" cx="578.1" cy="135" r="50" />
          <circle class="st0" cx="578.1" cy="135" r="25" />
          <circle class="st11" cx="187" cy="569.5" r="50" />
          <circle class="st13" cx="187" cy="569.5" r="25" />
          <circle class="st11" cx="592" cy="894.1" r="50" />
          <circle class="st13" cx="592" cy="894.1" r="25" />
          <circle class="st11" cx="512" cy="314" r="50" />
          <circle class="st13" cx="512" cy="314" r="25" />
          <circle class="st10" cx="329" cy="854.6" r="50" />
          <circle class="st12" cx="329" cy="854.6" r="25" />
        </svg>
        <div class="header-text">
          <h1>Dependency Radar</h1>
          <div class="header-meta">
            <span class="meta-item"><span class="meta-label">Project</span> <strong id="project-path">${escapeHtml(data.project.projectDir)}</strong></span>
            ${((_c = data.git) === null || _c === void 0 ? void 0 : _c.branch) ? `<span class="meta-item"><span class="meta-label">Branch</span> <strong>${escapeHtml(data.git.branch)}</strong></span>` : ''}
            ${nodeVersionText ? `<span class="meta-item"><span class="meta-label">Node</span> <strong>${escapeHtml(nodeVersionText)}</strong></span>` : ''}
            <span class="meta-item"><span class="meta-label">Generated</span> <strong id="formatted-date">${escapeHtml(formattedDate)}</strong></span>
            ${nodeDisclaimer ? `<span class="header-disclaimer">${escapeHtml(nodeDisclaimer)}</span>` : ''}
          </div>
        </div>
      </div>
      <div class="cta-section">
        <a href="https://dependency-radar.com" class="cta-link" target="_blank" rel="noopener">
          Get full analysis report
          <span class="cta-arrow">→</span>
        </a>
        <div class="cta-benefits">
          <span>AI-powered risk summary for stakeholders</span>
          <span>Charts & assets for presentations</span>
          <span>Actionable upgrade recommendations</span>
        </div>
        <div class="cta-text">dependency-radar.com</div>
      </div>
    </div>
  </header>
  
  <!-- Sticky Filter Bar -->
  <div class="filter-bar">
    <div class="filter-bar-inner">
      <div class="search-wrapper">
        <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
        </svg>
        <input type="search" id="search" placeholder="Search packages..." />
      </div>
      
      <div class="filter-group">
        <span class="filter-label">Type</span>
        <select id="direct-filter">
          <option value="all">All</option>
          <option value="direct">Dependency</option>
          <option value="transitive">Sub-Dependency</option>
        </select>
      </div>
      
      <div class="filter-group">
        <span class="filter-label">Scope</span>
        <select id="runtime-filter">
          <option value="all">All</option>
          <option value="runtime">Runtime</option>
          <option value="dev">Dev</option>
          <option value="optional">Optional</option>
          <option value="peer">Peer</option>
        </select>
      </div>
      
      <div class="filter-group sort-wrapper">
        <span class="filter-label">Sort</span>
        <select id="sort-by">
          <option value="name">Name</option>
          <option value="severity">Severity</option>
          <option value="depth">Depth</option>
        </select>
        <button type="button" class="sort-direction-btn" id="sort-direction" title="Toggle sort direction">↑</button>
      </div>
      
      <button type="button" class="license-filter-toggle" id="license-toggle">
        License Categories
        <span class="chevron">▼</span>
      </button>
      
      <label class="checkbox-filter">
        <input type="checkbox" id="has-vulns" />
        Has vulnerabilities
      </label>
      
      <div class="theme-toggle">
        <span class="theme-toggle-label">Theme</span>
        <div class="theme-switch" id="theme-switch" title="Toggle dark/light mode"></div>
      </div>
    </div>
    
    <!-- Collapsible License Filter Panel (inside sticky bar) -->
    <div class="license-filter-panel" id="license-panel">
      <div class="license-filter-inner">
        <div class="license-filter-header">
          <span class="license-filter-title">Filter by License Type</span>
          <div class="license-quick-actions">
            <button type="button" class="quick-action-btn" id="license-all">Show All</button>
            <button type="button" class="quick-action-btn" id="license-friendly">Business-Friendly Only</button>
          </div>
        </div>
        <div class="license-groups">
          <label class="license-group-checkbox">
            <input type="checkbox" id="license-permissive" checked />
            <span class="license-dot permissive"></span>
            Permissive (MIT, BSD, Apache, ISC)
          </label>
          <label class="license-group-checkbox">
            <input type="checkbox" id="license-weak-copyleft" checked />
            <span class="license-dot weak-copyleft"></span>
            Weak Copyleft (LGPL, MPL, EPL)
          </label>
          <label class="license-group-checkbox">
            <input type="checkbox" id="license-strong-copyleft" checked />
            <span class="license-dot strong-copyleft"></span>
            Strong Copyleft (GPL, AGPL)
          </label>
          <label class="license-group-checkbox">
            <input type="checkbox" id="license-unknown" checked />
            <span class="license-dot unknown"></span>
            Other / Unknown
          </label>
        </div>
      </div>
    </div>
  </div>
  
  <!-- Main Content -->
  <main class="main-content">
    <div class="results-summary" id="results-summary"></div>
    <div id="dependency-list" class="dependency-grid"></div>
  </main>

  <footer class="report-footer">
    <p><strong>About this report</strong></p>
    <p>Dependency Radar does not perform malware scanning or security auditing. It surfaces factual signals from dependency metadata, known vulnerabilities (npm audit), dependency graphs, and install-time behaviour to support informed review.</p>
  </footer>
  
  <script type="application/json" id="radar-data">${json}</script>
  <script>
${report_assets_1.JS_CONTENT}
  </script>
</body>
</html>`;
}
function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
