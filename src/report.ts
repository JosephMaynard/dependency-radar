import fs from 'fs/promises';
import path from 'path';
import { AggregatedData } from './types';
import { CSS_CONTENT, JS_CONTENT } from './report-assets';
import {
  MODULE_REPLACEMENTS_DATE,
  MODULE_REPLACEMENTS_VERSION,
} from './generated/replacements';
import { SPDX_LICENSE_LIST_RELEASE_DATE } from './generated/spdx';

/**
 * Escape occurrences of closing `</style` tags in a CSS payload to prevent premature termination when inlined into HTML.
 *
 * @param value - The CSS text to sanitize
 * @returns The sanitized string with each `</style` sequence replaced by `<\/style` (case-insensitive)
 */
function sanitizeInlineStyleTagPayload(value: string): string {
  return value.replace(/<\/style/gi, '<\\/style');
}

/**
 * Escapes closing `</script` sequences so a string can be embedded safely inside an inline `<script>` tag.
 *
 * @param value - The script content to sanitize
 * @returns The input with every `</script` (case-insensitive) replaced by `<\/script`
 */
function sanitizeInlineScriptTagPayload(value: string): string {
  return value.replace(/<\/script/gi, '<\\/script');
}

/**
 * Generate the HTML report from aggregated data and write it to the given file path.
 *
 * @param data - Aggregated radar data used to build the report
 * @param outputPath - Filesystem path where the generated HTML report will be written; parent directories are created if missing
 */
export async function renderReport(
  data: AggregatedData,
  outputPath: string,
): Promise<void> {
  const html = buildHtml(data);
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, html, 'utf8');
}

/**
 * Generate a complete standalone HTML document for the Dependency Radar report using the provided aggregated data.
 *
 * The returned document embeds sanitized inline CSS and JS, includes the JSON-serialized `data` (with `<` escaped), and formats `data.generatedAt` into a human-friendly timestamp when parsable. Interpolated values (for example `project.projectDir` and the formatted date) are HTML-escaped for safe embedding.
 *
 * @param data - AggregatedData used to populate the report; must include at least `project.projectDir`, `generatedAt`, and `dependencyRadarVersion`
 * @returns The full HTML document as a string
 */
function buildHtml(data: AggregatedData): string {
  const json = JSON.stringify(data).replace(/</g, '\\u003c');
  const safeCssContent = sanitizeInlineStyleTagPayload(CSS_CONTENT);
  const safeJsContent = sanitizeInlineScriptTagPayload(JS_CONTENT);

  // Format the generated date
  let formattedDate = data.generatedAt;
  try {
    const date = new Date(data.generatedAt);
    if (Number.isNaN(date.getTime())) {
      // Keep the original if parsing fails
    } else {
      formattedDate = new Intl.DateTimeFormat(undefined, {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      }).format(date);
    }
  } catch {
    // Keep the original if parsing fails
  }

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Dependency Radar</title>
  <link
    rel="icon"
    type="image/svg+xml"
      href="data:image/svg+xml;utf8,
        <svg xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' version='1.1' viewBox='0 0 1024 1024'>
          <defs>
            <style>
              .st0, .st1 {fill: %23ff8000;}
              .st2, .st3 {fill: %2340ff40;}
              .st3, .st4, .st1 {opacity: .4;}
              .st5 {fill: url(%23linear-gradient);}
              .st4, .st6 {fill: red;}
              .st7 {stroke-width: 16px;}
              .st7, .st8 {fill: %23171772;}
              .st7, .st8, .st9 {stroke: %2355fffa; stroke-miterlimit: 10;}
              .st8 {stroke-width: 10px;}
              .st10 {fill: %2314145e;}
              .st9 {fill: none; opacity: .3; stroke-width: 6px;}
              .st11 {fill: %2355fffa;}
            </style>
            <linearGradient id='linear-gradient' x1='239.3' y1='298.2' x2='815.3' y2='298.2' gradientTransform='translate(150 -115.1) rotate(15)' gradientUnits='userSpaceOnUse'>
              <stop offset='.4' stop-color='%2355fffa' stop-opacity='0'/>
              <stop offset='1' stop-color='%2355fffa' stop-opacity='.5'/>
            </linearGradient>
          </defs>
          <circle class='st10' cx='512' cy='512' r='512'/>
          <circle class='st7' cx='512' cy='512' r='430'/>
          <circle class='st8' cx='512' cy='512' r='256'/>
          <circle class='st9' cx='512' cy='512' r='160'/>
          <circle class='st9' cx='512' cy='512' r='379.5'/>
          <circle class='st9' cx='512' cy='512' r='339'/>
          <circle class='st9' cx='512' cy='512' r='210'/>
          <rect class='st11' x='690.2' y='193.1' width='15.8' height='427.6' transform='translate(701.4 -401.1) rotate(60)'/>
          <circle class='st11' cx='512' cy='514.4' r='64'/>
          <path class='st5' d='M517.2,513.4l365.8-213.9c-54.6-95.4-145.8-169.8-260.3-200.5-100.1-26.8-201.5-15.8-288.8,24.3l183.4,390Z'/>
          <circle class='st4' cx='512' cy='256' r='96'/>
          <circle class='st6' cx='512' cy='256' r='56'/>
          <circle class='st3' cx='733.7' cy='640' r='96' transform='translate(-237.7 706.3) rotate(-45)'/>
          <circle class='st2' cx='733.7' cy='640' r='56' transform='translate(-237.7 706.3) rotate(-45)'/>
          <ellipse class='st1' cx='290.3' cy='640' rx='96' ry='96' transform='translate(-367.5 392.7) rotate(-45)'/>
          <circle class='st0' cx='290.3' cy='640' r='56'/>
        </svg>"
  >
  <style>
${safeCssContent}
  </style>
</head>
<body>
  <!-- Top Header (Scrollable) -->
  <header class="top-header">
    <div class="header-row">
      <div class="header-content">
        <svg class="logo" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" viewBox="0 0 1024 1024">
          <defs>
            <style>
              .st0, .st1 {fill: #ff8000;}
              .st2, .st3 {fill: #40ff40;}
              .st3, .st4, .st1 {opacity: .4;}
              .st5 {fill: url(#linear-gradient);}
              .st4, .st6 {fill: red;}
              .st7 {stroke-width: 16px;}
              .st7, .st8 {fill: #171772;}
              .st7, .st8, .st9 {stroke: #55fffa; stroke-miterlimit: 10;}
              .st8 {stroke-width: 10px;}
              .st10 {fill: #14145e;}
              .st9 {fill: none; opacity: .3; stroke-width: 6px;}
              .st11 {fill: #55fffa;}
            </style>
            <linearGradient id="linear-gradient" x1="239.3" y1="298.2" x2="815.3" y2="298.2" gradientTransform="translate(150 -115.1) rotate(15)" gradientUnits="userSpaceOnUse">
              <stop offset=".4" stop-color="#55fffa" stop-opacity="0"/>
              <stop offset="1" stop-color="#55fffa" stop-opacity=".5"/>
            </linearGradient>
          </defs>
          <circle class="st10" cx="512" cy="512" r="512"/>
          <circle class="st7" cx="512" cy="512" r="430"/>
          <circle class="st8" cx="512" cy="512" r="256"/>
          <circle class="st9" cx="512" cy="512" r="160"/>
          <circle class="st9" cx="512" cy="512" r="379.5"/>
          <circle class="st9" cx="512" cy="512" r="339"/>
          <circle class="st9" cx="512" cy="512" r="210"/>
          <rect class="st11" x="690.2" y="193.1" width="15.8" height="427.6" transform="translate(701.4 -401.1) rotate(60)"/>
          <circle class="st11" cx="512" cy="514.4" r="64"/>
          <path class="st5" d="M517.2,513.4l365.8-213.9c-54.6-95.4-145.8-169.8-260.3-200.5-100.1-26.8-201.5-15.8-288.8,24.3l183.4,390Z"/>
          <circle class="st4" cx="512" cy="256" r="96"/>
          <circle class="st6" cx="512" cy="256" r="56"/>
          <circle class="st3" cx="733.7" cy="640" r="96" transform="translate(-237.7 706.3) rotate(-45)"/>
          <circle class="st2" cx="733.7" cy="640" r="56" transform="translate(-237.7 706.3) rotate(-45)"/>
          <ellipse class="st1" cx="290.3" cy="640" rx="96" ry="96" transform="translate(-367.5 392.7) rotate(-45)"/>
          <circle class="st0" cx="290.3" cy="640" r="56"/>
        </svg>
        <div class="header-text">
          <h1>Dependency Radar</h1>
          <div class="header-meta">
            <span class="meta-item"><span class="meta-label">Project</span> <strong id="project-path">${escapeHtml(data.project.projectDir)}</strong></span>
            <span class="meta-item"><span class="meta-label">Generated</span> <strong id="formatted-date">${escapeHtml(formattedDate)}</strong></span>
          </div>
        </div>
      </div>
      <div class="header-stats" id="header-stats" aria-label="Scan summary">
        <span class="stat-chip" id="stat-total"><span class="meta-label">Dependencies</span> <strong>–</strong></span>
        <button type="button" class="stat-chip" id="stat-vulnerable" data-stat-filter="has-vulns"><span class="meta-label">Vulnerable</span> <strong>–</strong></button>
        <button type="button" class="stat-chip" id="stat-maintenance" data-stat-filter="maintenance-concerns"><span class="meta-label">Maintenance</span> <strong>–</strong></button>
        <button type="button" class="stat-chip" id="stat-license" data-stat-filter="license-issues"><span class="meta-label">Licence issues</span> <strong>–</strong></button>
        <button type="button" class="stat-chip" id="stat-blockers" data-stat-filter="upgrade-blockers"><span class="meta-label">Upgrade blockers</span> <strong>–</strong></button>
        <button type="button" class="stat-chip" id="stat-replacements" data-stat-filter="has-replacement" hidden><span class="meta-label">Replacements</span> <strong>–</strong></button>
      </div>
    </div>
  </header>
  <div class="scan-status-banner" id="scan-status-banner" role="status" hidden></div>
  
  <!-- Sticky Filter Bar -->
  <div class="filter-bar">
    <div class="filter-bar-inner">
      <div class="filter-row">
        <div class="filter-top-row">
          <div class="search-wrapper">
            <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
            </svg>
            <input type="search" id="search" placeholder="Search packages..." aria-label="Search packages" />
          </div>
          <button
            type="button"
            class="filters-toggle"
            id="filters-toggle"
            aria-expanded="false"
            aria-controls="filter-controls"
          >
            Filters
            <span class="filter-count-badge" id="filter-count-badge" hidden></span>
            <span class="chevron">▼</span>
          </button>
          <button
            type="button"
            class="filters-toggle metadata-toggle"
            id="metadata-toggle"
            aria-expanded="false"
            aria-controls="metadata-panel"
          >
            Metadata
            <span class="chevron">▼</span>
          </button>
          <div class="view-switch" id="view-switch">
            <button
              type="button"
              class="view-switch-btn"
              id="view-graph-btn"
              data-view="graph"
            >
              Graph View
            </button>
          </div>
          <div class="theme-toggle">
            <span class="theme-toggle-label">Theme</span>
            <button
              type="button"
              class="theme-switch"
              id="theme-switch"
              aria-label="Toggle dark/light mode"
              aria-pressed="false"
            ></button>
          </div>
        </div>

        <div class="filter-controls" id="filter-controls" role="dialog" aria-label="Dependency filters" aria-hidden="true" inert>
          <div class="filter-controls-row">
            <div class="filter-panel-section">
              <div class="filter-panel-title">Dependency</div>
            <div class="filter-group">
              <label class="filter-label" for="direct-filter">Type</label>
              <select id="direct-filter">
                <option value="all">All</option>
                <option value="direct">Dependency</option>
                <option value="transitive">Sub-Dependency</option>
              </select>
            </div>

            <div class="filter-group">
              <label class="filter-label" for="runtime-filter">Scope</label>
              <select id="runtime-filter">
                <option value="all">All</option>
                <option value="runtime">Runtime</option>
                <option value="dev">Dev</option>
                <option value="optional">Optional</option>
                <option value="peer">Peer</option>
              </select>
            </div>
            </div>

            <div class="filter-panel-section filter-panel-context">
              <div class="filter-panel-title">Context</div>
            <div class="filter-group workspace-filter-group hidden" id="workspace-filter-wrap">
              <label class="filter-label" for="workspace-filter">Workspace</label>
              <select id="workspace-filter">
                <option value="all">All workspaces</option>
              </select>
            </div>
            </div>

            <div class="filter-panel-section">
              <div class="filter-panel-title">Risk</div>
              <div class="license-filter-panel" id="license-panel">
                <div class="license-filter-inner">
                  <div class="license-filter-header">
                    <span class="license-filter-title">License categories</span>
                    <div class="license-quick-actions">
                      <button type="button" class="quick-action-btn" id="license-all">Show All</button>
                      <button type="button" class="quick-action-btn" id="license-friendly">Business-Friendly Only</button>
                    </div>
                  </div>
                  <div class="license-groups">
                    <label class="license-group-checkbox">
                      <input type="checkbox" id="license-permissive" checked />
                      <span class="license-dot permissive"></span>
                      <span id="license-permissive-label">Permissive</span>
                    </label>
                    <label class="license-group-checkbox">
                      <input type="checkbox" id="license-weak-copyleft" checked />
                      <span class="license-dot weak-copyleft"></span>
                      <span id="license-weak-copyleft-label">Weak Copyleft</span>
                    </label>
                    <label class="license-group-checkbox">
                      <input type="checkbox" id="license-strong-copyleft" checked />
                      <span class="license-dot strong-copyleft"></span>
                      <span id="license-strong-copyleft-label">Strong Copyleft</span>
                    </label>
                    <label class="license-group-checkbox">
                      <input type="checkbox" id="license-unknown" checked />
                      <span class="license-dot unknown"></span>
                      <span id="license-unknown-label">Other / Unknown</span>
                    </label>
                  </div>
                </div>
              </div>

              <label class="checkbox-filter">
                <input type="checkbox" id="has-vulns" />
                <span id="has-vulns-label">Has vulnerabilities</span>
              </label>

              <label class="checkbox-filter">
                <input type="checkbox" id="maintenance-concerns" />
                <span id="maintenance-concerns-label">Maintenance concerns</span>
              </label>

              <label class="checkbox-filter">
                <input type="checkbox" id="license-issues" />
                <span id="license-issues-label">Licence issues</span>
              </label>

              <label class="checkbox-filter">
                <input type="checkbox" id="upgrade-blockers" />
                <span id="upgrade-blockers-label">Upgrade blockers</span>
              </label>

              <span class="checkbox-filter">
                <input type="checkbox" id="no-imports" />
                <label for="no-imports" id="no-imports-label">No imports found</label>
                <button type="button" class="fine-print-btn" data-fine-topic="imports" aria-haspopup="true" aria-expanded="false" aria-label="About: Import evidence">ⓘ</button>
              </span>

              <label class="checkbox-filter">
                <input type="checkbox" id="duplicate-versions" />
                <span id="duplicate-versions-label">Duplicate versions</span>
              </label>

              <label class="checkbox-filter" id="has-replacement-wrap" hidden>
                <input type="checkbox" id="has-replacement" />
                <span id="has-replacement-label">Has replacement suggestion</span>
              </label>
            </div>

            <!-- Sort dropdown - visible on mobile, hidden on desktop (replaced by column headers) -->
            <div class="filter-group sort-wrapper mobile-only" id="mobile-sort">
              <label class="filter-label" for="sort-by">SORT</label>
              <select id="sort-by" aria-label="Sort dependencies by">
                <option value="name">Name</option>
                <option value="type">Type</option>
                <option value="scope">Scope</option>
                <option value="license">License</option>
                <option value="severity">Severity</option>
                <option value="install">Install</option>
                <option value="maintenance">Maintenance</option>
                <option value="depth">Depth</option>
                <option value="subdeps">Sub-deps</option>
                <option value="frees">Frees</option>
              </select>
              <button type="button" class="sort-direction-btn" id="sort-direction" title="Toggle sort direction" aria-label="Toggle sort direction">↑</button>
            </div>

            <div class="filter-panel-actions">
              <button type="button" class="quick-action-btn" id="clear-all-filters">Clear all filters</button>
            </div>
          </div>
        </div>

        <div class="metadata-panel" id="metadata-panel" role="dialog" aria-label="Report metadata" hidden></div>

        <div class="active-filters-row" id="active-filters-row" hidden>
          <span class="active-filters-label">Active filters:</span>
          <div class="active-filter-chips" id="active-filter-chips"></div>
          <button type="button" class="active-filter-clear" id="active-filter-clear">Clear all</button>
        </div>

        <!-- Results summary and column headers row -->
        <div class="column-headers-section" id="column-headers-section">
          <div class="package-header-wrapper">
            <div class="results-summary" id="results-summary"></div>
            <button type="button" class="column-header package-header column-header-no-border" data-sort="name" id="package-header">
              PACKAGE
              <span class="sort-indicator"></span>
            </button>
          </div>
          <!-- Column headers are dynamically generated by JavaScript from COLUMN_CONFIG -->
          <div id="column-headers-container"></div>
        </div>
      </div>
    </div>
  </div>
  
  <!-- Main Content -->
  <main class="main-content">
    <section class="view-panel active" id="list-view" data-view="list" aria-hidden="false">
      <div id="dependency-list" class="dependency-grid"></div>
    </section>
    <section class="view-panel" id="graph-view" data-view="graph" aria-hidden="true">
            <div class="graph-canvas-shell" id="graph-canvas-shell">
        <canvas id="graph-canvas"></canvas>
        <div class="graph-alt-host" id="graph-alt-host" hidden></div>
        <div class="graph-status-line dim" id="graph-status-line"></div>
        <div class="graph-overlay-top">
          <button type="button" class="graph-back-btn" id="graph-back-btn">Back to List View</button>
          <div class="graph-mode-switch" id="graph-mode-switch" role="group" aria-label="Graph layout">
            <button type="button" class="graph-mode-btn active" data-graph-mode="graph" aria-pressed="true">Graph</button>
            <button type="button" class="graph-mode-btn" data-graph-mode="flame" aria-pressed="false">Flame</button>
            <button type="button" class="graph-mode-btn" data-graph-mode="treemap" aria-pressed="false">Treemap</button>
            <button type="button" class="graph-mode-btn" data-graph-mode="balloon" aria-pressed="false">Balloon</button>
            <button type="button" class="graph-mode-btn" data-graph-mode="hyperbolic" aria-pressed="false">Hyperbolic</button>
          </div>
          <div class="graph-key" id="graph-key">
            <button type="button" class="graph-key-toggle" id="graph-key-toggle" aria-expanded="false" aria-controls="graph-key-panel">
              Key
              <span class="chevron" aria-hidden="true">▼</span>
            </button>
            <div class="graph-key-panel" id="graph-key-panel" role="group" aria-label="Graph key" hidden>
              <div class="graph-key-items">
                <span class="graph-key-item">
                  <span class="graph-key-dot dependency" aria-hidden="true"></span>
                  <span>Dependency</span>
                </span>
                <span class="graph-key-item">
                  <span class="graph-key-dot dev-dependency" aria-hidden="true"></span>
                  <span>Dev-Dependency</span>
                </span>
                <span class="graph-key-item">
                  <span class="graph-key-dot sub-dependency" aria-hidden="true"></span>
                  <span>Sub-Dependency</span>
                </span>
              <span class="graph-key-item">
            <span>Circle size: removal impact and connection count</span>
          </span>
          <span class="graph-key-item">
            <span class="graph-key-line route" aria-hidden="true"></span>
            <span>Selection: routes keeping it installed</span>
          </span>
          <span class="graph-key-item">
            <span class="graph-key-line deps" aria-hidden="true"></span>
            <span>Selection: what it depends on</span>
          </span>
        </div>
            </div>
          </div>
          <div class="graph-filter-wrap" id="graph-filter-wrap">
            <button type="button" class="graph-key-toggle" id="graph-filters-toggle" aria-expanded="false" aria-controls="graph-filters-panel">
              Filters
              <span class="graph-toggle-badge" id="graph-filters-badge" hidden></span>
              <span class="chevron" aria-hidden="true">▼</span>
            </button>
            <div class="graph-key-panel graph-filters-panel" id="graph-filters-panel" role="group" aria-label="Graph filters" hidden>
              <div class="graph-panel-section-title">Show</div>
              <div class="graph-filter-items">
                <button type="button" class="graph-filter-chip" id="graph-filter-runtime" aria-pressed="true">
                  <span class="graph-key-dot dependency" aria-hidden="true"></span>
                  Runtime
                </button>
                <button type="button" class="graph-filter-chip" id="graph-filter-dev" aria-pressed="true">
                  <span class="graph-key-dot dev-dependency" aria-hidden="true"></span>
                  Dev
                </button>
                <button type="button" class="graph-filter-chip" id="graph-filter-sub" aria-pressed="true">
                  <span class="graph-key-dot sub-dependency" aria-hidden="true"></span>
                  Sub-deps
                </button>
                <select id="graph-filter-depth" class="graph-workspace-select graph-depth-select" aria-label="Maximum dependency depth">
                  <option value="">All depths</option>
                  <option value="1">Depth ≤ 1</option>
                  <option value="2">Depth ≤ 2</option>
                  <option value="3">Depth ≤ 3</option>
                  <option value="4">Depth ≤ 4</option>
                  <option value="5">Depth ≤ 5</option>
                </select>
              </div>
              <div class="graph-panel-section-title">Highlight</div>
              <div class="graph-filter-items">
                <button type="button" class="graph-filter-chip" id="graph-hl-vuln" aria-pressed="false">
                  <span class="graph-key-dot hl-vuln" aria-hidden="true"></span>
                  Vulnerable
                </button>
                <button type="button" class="graph-filter-chip" id="graph-hl-maintenance" aria-pressed="false">
                  <span class="graph-key-dot hl-maintenance" aria-hidden="true"></span>
                  Maintenance concern
                </button>
                <button type="button" class="graph-filter-chip" id="graph-hl-replacement" aria-pressed="false">
                  <span class="graph-key-dot hl-replacement" aria-hidden="true"></span>
                  Replacement suggested
                </button>
                <button type="button" class="graph-filter-chip" id="graph-hl-license" aria-pressed="false">
                  <span class="graph-key-dot hl-license" aria-hidden="true"></span>
                  Licence issue
                </button>
                <button type="button" class="graph-filter-chip" id="graph-hl-blocker" aria-pressed="false">
                  <span class="graph-key-dot hl-blocker" aria-hidden="true"></span>
                  Upgrade blocker
                </button>
                <button type="button" class="graph-filter-chip" id="graph-hl-unused" aria-pressed="false">
                  <span class="graph-key-dot hl-unused" aria-hidden="true"></span>
                  No imports found
                </button>
                <button type="button" class="graph-filter-chip" id="graph-hl-duplicate" aria-pressed="false">
                  <span class="graph-key-dot hl-duplicate" aria-hidden="true"></span>
                  Duplicate versions
                </button>
              </div>
              <button type="button" class="graph-panel-reset" id="graph-filters-reset">
                Reset filters
              </button>
            </div>
          </div>
          <div class="graph-workspace-wrap" id="graph-workspace-wrap">
            <label class="graph-workspace-label" for="graph-workspace">Workspace</label>
            <select id="graph-workspace" class="graph-workspace-select"></select>
          </div>
        </div>
        <div class="graph-controls graph-overlay graph-overlay-right" id="graph-controls">
          <div class="dpad">
            <button type="button" class="graph-control-btn up" data-action="pan-down" aria-label="Pan Up">▲</button>
            <button type="button" class="graph-control-btn left" data-action="pan-right" aria-label="Pan Left">◀</button>
            <div class="center-spacer" aria-hidden="true"></div>
            <button type="button" class="graph-control-btn right" data-action="pan-left" aria-label="Pan Right">▶</button>
            <button type="button" class="graph-control-btn down" data-action="pan-up" aria-label="Pan Down">▼</button>
          </div>
          <div class="zoom-controls">
            <button type="button" class="graph-control-btn" data-action="zoom-in" aria-label="Zoom In">+</button>
            <button type="button" class="graph-control-btn" data-action="zoom-out" aria-label="Zoom Out">−</button>
          </div>
          <button type="button" class="graph-control-btn reset-btn" data-action="reset">reset</button>
        </div>
        <aside class="graph-side-panel" id="graph-side-panel" aria-label="Selection details">
          <div class="graph-side-search">
            <input id="graph-search" type="search" placeholder="Find a package…" autocomplete="off" aria-label="Find a package" />
            <ul id="graph-search-results" class="graph-search-results"></ul>
          </div>
          <div class="graph-dossier" id="graph-dossier"></div>
        </aside>
      </div>
    </section>
  </main>

  <footer class="report-footer">
    <p><strong>About this report</strong></p>
    <p>Dependency Radar does not perform malware scanning or security auditing. It surfaces factual signals from dependency metadata, known vulnerabilities (npm audit), dependency graphs, and install-time behaviour to support informed review.</p>
    <p class="report-footer-vintage">Dependency Radar v${escapeHtml(data.dependencyRadarVersion)} \u00b7 report created ${escapeHtml(formattedDate)}. Bundled definitions: SPDX licence list (${SPDX_LICENSE_LIST_RELEASE_DATE}) · e18e module-replacements ${MODULE_REPLACEMENTS_VERSION} (${MODULE_REPLACEMENTS_DATE}).</p>
  </footer>
  
  <script type="application/json" id="radar-data">${json}</script>
<script>
${safeJsContent}
</script>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
