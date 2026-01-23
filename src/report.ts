import fs from 'fs/promises';
import path from 'path';
import { AggregatedData } from './types';

export async function renderReport(data: AggregatedData, outputPath: string): Promise<void> {
  const html = buildHtml(data);
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, html, 'utf8');
}

function buildHtml(data: AggregatedData): string {
  const json = JSON.stringify(data).replace(/</g, '\\u003c');
  const gitBranchHtml = data.gitBranch ? `<br/>Branch: <strong>${escapeHtml(data.gitBranch)}</strong>` : '';
  
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Dependency Radar</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    
    :root {
      /* Dark theme (default) */
      --bg-primary: #0f172a;
      --bg-secondary: #1e293b;
      --bg-card: rgba(30, 41, 59, 0.8);
      --bg-card-hover: rgba(51, 65, 85, 0.9);
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --border-color: rgba(148, 163, 184, 0.2);
      --border-color-strong: rgba(148, 163, 184, 0.4);
      --accent: #3b82f6;
      --accent-hover: #60a5fa;
      
      /* Status colors */
      --green: #22c55e;
      --green-bg: rgba(34, 197, 94, 0.15);
      --amber: #f59e0b;
      --amber-bg: rgba(245, 158, 11, 0.15);
      --red: #ef4444;
      --red-bg: rgba(239, 68, 68, 0.15);
      --gray: #64748b;
      --gray-bg: rgba(100, 116, 139, 0.15);
      
      /* License category colors */
      --license-permissive: #22c55e;
      --license-weak-copyleft: #f59e0b;
      --license-strong-copyleft: #ef4444;
      --license-unknown: #64748b;
      
      --font-stack: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace;
      --transition: 0.2s ease;
      --radius: 8px;
      --radius-lg: 12px;
    }
    
    :root.light {
      --bg-primary: #f8fafc;
      --bg-secondary: #e2e8f0;
      --bg-card: rgba(255, 255, 255, 0.9);
      --bg-card-hover: rgba(241, 245, 249, 1);
      --text-primary: #0f172a;
      --text-secondary: #475569;
      --text-muted: #64748b;
      --border-color: rgba(100, 116, 139, 0.2);
      --border-color-strong: rgba(100, 116, 139, 0.4);
    }
    
    html { scroll-behavior: smooth; }
    
    body {
      font-family: var(--font-stack);
      background: var(--bg-primary);
      color: var(--text-primary);
      margin: 0;
      padding: 0;
      line-height: 1.5;
      transition: background var(--transition), color var(--transition);
    }
    
    /* ===== TOP HEADER (Scrollable) ===== */
    .top-header {
      padding: 24px 24px 16px;
      max-width: 1400px;
      margin: 0 auto;
    }
    
    .header-row {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 24px;
    }
    
    .header-content {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    
    .logo, .logo-wrapper {
      display: block;
      width: 72px;
      height: 72px;
      flex-shrink: 0;
    }
    
    .logo svg {
      width: 100%;
      height: 100%;
    }
    
    .header-text h1 {
      margin: 0;
      font-size: 28px;
      font-weight: 700;
      background: linear-gradient(135deg, var(--accent) 0%, #a855f7 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    
    .header-meta {
      margin-top: 4px;
      font-size: 13px;
      color: var(--text-secondary);
    }
    
    .header-meta strong {
      color: var(--text-primary);
      font-family: var(--font-mono);
      font-size: 12px;
    }
    
    /* CTA Button */
    .cta-section {
      flex-shrink: 0;
      text-align: right;
    }
    
    .cta-link {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 12px 20px;
      background: linear-gradient(135deg, #8b5cf6 0%, #ec4899 100%);
      color: white;
      text-decoration: none;
      border-radius: var(--radius-lg);
      font-size: 14px;
      font-weight: 600;
      transition: transform var(--transition), box-shadow var(--transition);
      box-shadow: 0 4px 14px rgba(139, 92, 246, 0.4);
    }
    
    .cta-link:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(139, 92, 246, 0.5);
    }
    
    .cta-text {
      display: block;
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 6px;
    }
    
    .cta-arrow {
      font-size: 16px;
    }
    
    /* ===== STICKY FILTER BAR ===== */
    .filter-bar {
      position: sticky;
      top: 0;
      z-index: 100;
      background: var(--bg-secondary);
      border-bottom: 1px solid var(--border-color);
      backdrop-filter: blur(12px);
      padding: 12px 24px;
      transition: background var(--transition), border-color var(--transition);
    }
    
    .filter-bar-inner {
      max-width: 1400px;
      margin: 0 auto;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 12px;
    }
    
    .filter-group {
      display: flex;
      align-items: center;
      gap: 6px;
    }
    
    .filter-label {
      font-size: 12px;
      font-weight: 500;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .search-wrapper {
      position: relative;
      flex: 1;
      min-width: 180px;
      max-width: 280px;
    }
    
    .search-icon {
      position: absolute;
      left: 10px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-muted);
      pointer-events: none;
    }
    
    input[type="search"] {
      width: 100%;
      padding: 8px 12px 8px 32px;
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      background: var(--bg-primary);
      color: var(--text-primary);
      font-size: 14px;
      transition: border-color var(--transition), background var(--transition);
    }
    
    input[type="search"]:focus {
      outline: none;
      border-color: var(--accent);
    }
    
    input[type="search"]::placeholder {
      color: var(--text-muted);
    }
    
    select {
      padding: 8px 28px 8px 10px;
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      background: var(--bg-primary);
      color: var(--text-primary);
      font-size: 13px;
      cursor: pointer;
      appearance: none;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right 8px center;
      transition: border-color var(--transition), background var(--transition);
    }
    
    select:focus {
      outline: none;
      border-color: var(--accent);
    }
    
    .sort-wrapper {
      display: flex;
      align-items: center;
      gap: 4px;
    }
    
    .sort-direction-btn {
      padding: 8px;
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      background: var(--bg-primary);
      color: var(--text-secondary);
      cursor: pointer;
      font-size: 14px;
      line-height: 1;
      transition: all var(--transition);
    }
    
    .sort-direction-btn:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    
    .checkbox-filter {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      color: var(--text-secondary);
      cursor: pointer;
    }
    
    .checkbox-filter input[type="checkbox"] {
      width: 16px;
      height: 16px;
      accent-color: var(--accent);
      cursor: pointer;
    }
    
    /* Theme toggle */
    .theme-toggle {
      margin-left: auto;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .theme-toggle-label {
      font-size: 12px;
      color: var(--text-muted);
    }
    
    .theme-switch {
      position: relative;
      width: 44px;
      height: 24px;
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      cursor: pointer;
      transition: background var(--transition), border-color var(--transition);
    }
    
    .theme-switch::after {
      content: '';
      position: absolute;
      top: 2px;
      left: 2px;
      width: 18px;
      height: 18px;
      background: var(--text-secondary);
      border-radius: 50%;
      transition: transform var(--transition), background var(--transition);
    }
    
    .theme-switch.light::after {
      transform: translateX(20px);
      background: var(--accent);
    }
    
    /* ===== COLLAPSIBLE LICENSE FILTER ===== */
    .license-filter-toggle {
      padding: 6px 12px;
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      background: transparent;
      color: var(--text-secondary);
      font-size: 12px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      transition: all var(--transition);
    }
    
    .license-filter-toggle:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    
    .license-filter-toggle .chevron {
      transition: transform var(--transition);
    }
    
    .license-filter-toggle.open .chevron {
      transform: rotate(180deg);
    }
    
    .license-filter-panel {
      max-height: 0;
      overflow: hidden;
      transition: max-height 0.3s ease-out;
      background: var(--bg-secondary);
      border-bottom: 1px solid transparent;
    }
    
    .license-filter-panel.open {
      max-height: 200px;
      border-bottom-color: var(--border-color);
    }
    
    .license-filter-inner {
      max-width: 1400px;
      margin: 0 auto;
      padding: 12px 24px;
    }
    
    .license-filter-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 8px;
    }
    
    .license-filter-title {
      font-size: 12px;
      font-weight: 500;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .license-quick-actions {
      display: flex;
      gap: 8px;
    }
    
    .quick-action-btn {
      padding: 4px 10px;
      font-size: 11px;
      border: 1px solid var(--border-color);
      border-radius: 4px;
      background: transparent;
      color: var(--text-secondary);
      cursor: pointer;
      transition: all var(--transition);
    }
    
    .quick-action-btn:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    
    .license-groups {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
    }
    
    .license-group-checkbox {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      color: var(--text-secondary);
      cursor: pointer;
    }
    
    .license-group-checkbox input[type="checkbox"] {
      width: 16px;
      height: 16px;
      accent-color: var(--accent);
      cursor: pointer;
    }
    
    .license-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      flex-shrink: 0;
    }
    
    .license-dot.permissive { background: var(--license-permissive); }
    .license-dot.weak-copyleft { background: var(--license-weak-copyleft); }
    .license-dot.strong-copyleft { background: var(--license-strong-copyleft); }
    .license-dot.unknown { background: var(--license-unknown); }
    
    /* ===== TOOL ERRORS ===== */
    .tool-errors {
      max-width: 1400px;
      margin: 16px auto;
      padding: 12px 16px;
      background: var(--red-bg);
      border: 1px solid var(--red);
      border-radius: var(--radius);
      color: var(--red);
    }
    
    .tool-errors strong {
      display: block;
      margin-bottom: 8px;
    }
    
    /* ===== MAIN CONTENT ===== */
    .main-content {
      max-width: 1400px;
      margin: 0 auto;
      padding: 16px 24px 48px;
    }
    
    .results-summary {
      margin-bottom: 16px;
      font-size: 14px;
      color: var(--text-secondary);
    }
    
    .results-summary strong {
      color: var(--text-primary);
    }
    
    .dependency-grid {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    
    /* ===== DEPENDENCY CARD ===== */
    .dep-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-lg);
      overflow: hidden;
      transition: all var(--transition);
    }
    
    .dep-card:hover {
      background: var(--bg-card-hover);
      border-color: var(--border-color-strong);
    }
    
    .dep-card[data-risk="red"] {
      border-left: 3px solid var(--red);
    }
    
    .dep-card[data-risk="amber"] {
      border-left: 3px solid var(--amber);
    }
    
    .dep-card[data-risk="green"] {
      border-left: 3px solid var(--green);
    }
    
    .dep-summary {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px 16px;
      cursor: pointer;
      list-style: none;
    }
    
    .dep-summary::-webkit-details-marker { display: none; }
    
    .expand-icon {
      color: var(--text-muted);
      transition: transform var(--transition);
      flex-shrink: 0;
    }
    
    details[open] .expand-icon {
      transform: rotate(90deg);
    }
    
    .dep-name {
      font-family: var(--font-mono);
      font-size: 14px;
      font-weight: 600;
      color: var(--text-primary);
    }
    
    .dep-version {
      font-weight: 400;
      color: var(--text-secondary);
    }
    
    .dep-indicators {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 16px;
      margin-left: auto;
    }
    
    .indicator {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
      color: var(--text-secondary);
    }
    
    .indicator-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      flex-shrink: 0;
    }
    
    .indicator-dot.green { background: var(--green); }
    .indicator-dot.amber { background: var(--amber); }
    .indicator-dot.red { background: var(--red); }
    .indicator-dot.gray { background: var(--gray); }
    
    .indicator-separator {
      width: 1px;
      height: 16px;
      background: var(--border-color);
    }
    
    /* ===== EXPANDED DETAILS ===== */
    .dep-details {
      padding: 0 16px 16px 16px;
      border-top: 1px solid var(--border-color);
      animation: slideDown 0.2s ease-out;
    }
    
    @keyframes slideDown {
      from {
        opacity: 0;
        transform: translateY(-8px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    
    .section {
      margin-top: 16px;
    }
    
    .section:first-child {
      margin-top: 16px;
    }
    
    .section-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 10px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--border-color);
    }
    
    .section-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-primary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .section-desc {
      font-size: 11px;
      color: var(--text-muted);
    }
    
    .kv-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 12px;
    }
    
    .kv-item {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    
    .kv-label {
      font-size: 12px;
      font-weight: 500;
      color: var(--text-muted);
    }
    
    .kv-value {
      font-size: 14px;
      color: var(--text-primary);
    }
    
    .kv-hint {
      font-size: 11px;
      color: var(--text-muted);
      font-style: italic;
    }
    
    /* Package list in graph section */
    .package-list {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 4px;
    }
    
    .package-tag {
      padding: 2px 8px;
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      font-size: 11px;
      font-family: var(--font-mono);
      color: var(--text-secondary);
    }
    
    .package-list-toggle {
      font-size: 11px;
      color: var(--accent);
      background: none;
      border: none;
      cursor: pointer;
      padding: 2px 4px;
    }
    
    .package-list-toggle:hover {
      text-decoration: underline;
    }
    
    /* Vulnerability table */
    .vuln-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    
    .vuln-table th,
    .vuln-table td {
      text-align: left;
      padding: 8px 12px;
      border-bottom: 1px solid var(--border-color);
    }
    
    .vuln-table th {
      font-weight: 500;
      color: var(--text-muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .vuln-table tr[data-severity="critical"],
    .vuln-table tr[data-severity="high"] {
      background: var(--red-bg);
    }
    
    .vuln-table tr[data-severity="moderate"] {
      background: var(--amber-bg);
    }
    
    .vuln-table a {
      color: var(--accent);
      text-decoration: none;
    }
    
    .vuln-table a:hover {
      text-decoration: underline;
    }
    
    .no-vulns {
      font-size: 13px;
      color: var(--text-secondary);
      padding: 8px 0;
    }
    
    /* Raw data toggle */
    .raw-data-toggle {
      margin-top: 16px;
    }
    
    .raw-data-toggle summary {
      font-size: 12px;
      color: var(--text-muted);
      cursor: pointer;
      padding: 8px 0;
    }
    
    .raw-data-toggle pre {
      margin: 8px 0 0 0;
      padding: 12px;
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-secondary);
      overflow-x: auto;
      max-height: 300px;
    }
    
    /* Empty state */
    .empty-state {
      text-align: center;
      padding: 48px 24px;
      color: var(--text-muted);
    }
    
    .empty-state-icon {
      font-size: 48px;
      margin-bottom: 12px;
    }
    
    .empty-state-text {
      font-size: 16px;
    }
    
    /* ===== RESPONSIVE ===== */
    @media (max-width: 768px) {
      .header-row {
        flex-direction: column;
        align-items: flex-start;
      }
      
      .cta-section {
        text-align: left;
      }
      
      .filter-bar-inner {
        flex-direction: column;
        align-items: stretch;
      }
      
      .search-wrapper {
        max-width: none;
      }
      
      .theme-toggle {
        margin-left: 0;
        justify-content: flex-end;
      }
      
      .dep-indicators {
        flex-wrap: wrap;
        gap: 8px;
      }
      
      .indicator-separator {
        display: none;
      }
    }
  </style>
</head>
<body>
  <!-- Top Header (Scrollable) -->
  <header class="top-header">
    <div class="header-row">
      <div class="header-content">
        <div class="logo">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
            <defs>
              <linearGradient id="logoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:#3b82f6"/>
                <stop offset="100%" style="stop-color:#a855f7"/>
              </linearGradient>
            </defs>
            <circle cx="50" cy="50" r="45" fill="none" stroke="url(#logoGrad)" stroke-width="4"/>
            <circle cx="50" cy="50" r="30" fill="none" stroke="url(#logoGrad)" stroke-width="3" opacity="0.7"/>
            <circle cx="50" cy="50" r="15" fill="none" stroke="url(#logoGrad)" stroke-width="2" opacity="0.5"/>
            <circle cx="50" cy="50" r="5" fill="url(#logoGrad)"/>
            <line x1="50" y1="5" x2="50" y2="20" stroke="url(#logoGrad)" stroke-width="2" opacity="0.5"/>
            <line x1="50" y1="80" x2="50" y2="95" stroke="url(#logoGrad)" stroke-width="2" opacity="0.5"/>
            <line x1="5" y1="50" x2="20" y2="50" stroke="url(#logoGrad)" stroke-width="2" opacity="0.5"/>
            <line x1="80" y1="50" x2="95" y2="50" stroke="url(#logoGrad)" stroke-width="2" opacity="0.5"/>
          </svg>
        </div>
        <div class="header-text">
          <h1>Dependency Radar</h1>
          <p class="header-meta">
            Project: <strong>${escapeHtml(data.projectPath)}</strong>${gitBranchHtml}<br/>
            Generated: <span id="formatted-date">${data.generatedAt}</span>
          </p>
        </div>
      </div>
      <div class="cta-section">
        <a href="https://dependency-radar.com" class="cta-link" target="_blank" rel="noopener">
          Get risk analysis & summary
          <span class="cta-arrow">→</span>
        </a>
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
        <span class="filter-label">Runtime</span>
        <select id="runtime-filter">
          <option value="all">All</option>
          <option value="runtime">Runtime</option>
          <option value="build-time">Build-time</option>
          <option value="dev-only">Dev-only</option>
        </select>
      </div>
      
      <div class="filter-group sort-wrapper">
        <span class="filter-label">Sort</span>
        <select id="sort-by">
          <option value="name">Name</option>
          <option value="severity">Severity</option>
          <option value="depth">Depth</option>
          <option value="size">Size</option>
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
      
      <label class="checkbox-filter">
        <input type="checkbox" id="unused-only" />
        Unused only
      </label>
      
      <div class="theme-toggle">
        <span class="theme-toggle-label">Theme</span>
        <div class="theme-switch" id="theme-switch" title="Toggle dark/light mode"></div>
      </div>
    </div>
  </div>
  
  <!-- Collapsible License Filter Panel -->
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
  
  ${renderToolErrors(data)}
  
  <!-- Main Content -->
  <main class="main-content">
    <div class="results-summary" id="results-summary"></div>
    <div id="dependency-list" class="dependency-grid"></div>
  </main>
  
  <script type="application/json" id="radar-data">${json}</script>
  <script>
    (function() {
      const dataEl = document.getElementById('radar-data');
      const report = JSON.parse(dataEl.textContent || '{}');
      const maintenanceEnabled = Boolean(report.maintenanceEnabled);
      const container = document.getElementById('dependency-list');
      const summaryEl = document.getElementById('results-summary');
      
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
        } catch (e) {
          // Fallback: keep ISO format
        }
      }
      
      // License categorization
      const LICENSE_CATEGORIES = {
        permissive: ['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', 'Unlicense', '0BSD', 'CC0-1.0', 'BSD', 'Apache', 'Apache 2.0', 'Apache License 2.0', 'MIT License', 'ISC License'],
        weakCopyleft: ['LGPL-2.1', 'LGPL-3.0', 'LGPL-2.0', 'LGPL', 'MPL-2.0', 'MPL-1.1', 'MPL', 'EPL-1.0', 'EPL-2.0', 'EPL'],
        strongCopyleft: ['GPL-2.0', 'GPL-3.0', 'GPL', 'AGPL-3.0', 'AGPL', 'GPL-2.0-only', 'GPL-3.0-only', 'GPL-2.0-or-later', 'GPL-3.0-or-later']
      };
      
      function getLicenseCategory(license) {
        if (!license) return 'unknown';
        const normalized = license.toUpperCase();
        for (const [cat, licenses] of Object.entries(LICENSE_CATEGORIES)) {
          if (licenses.some(l => normalized.includes(l.toUpperCase()))) return cat;
        }
        return 'unknown';
      }
      
      // Controls
      const controls = {
        search: document.getElementById('search'),
        direct: document.getElementById('direct-filter'),
        runtime: document.getElementById('runtime-filter'),
        sort: document.getElementById('sort-by'),
        sortDirection: document.getElementById('sort-direction'),
        hasVulns: document.getElementById('has-vulns'),
        unusedOnly: document.getElementById('unused-only'),
        themeSwitch: document.getElementById('theme-switch'),
        licenseToggle: document.getElementById('license-toggle'),
        licensePanel: document.getElementById('license-panel'),
        licensePermissive: document.getElementById('license-permissive'),
        licenseWeakCopyleft: document.getElementById('license-weak-copyleft'),
        licenseStrongCopyleft: document.getElementById('license-strong-copyleft'),
        licenseUnknown: document.getElementById('license-unknown'),
        licenseAll: document.getElementById('license-all'),
        licenseFriendly: document.getElementById('license-friendly')
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
      
      function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
      }
      
      function getHighestRisk(dep) {
        const risks = [dep.vulnRisk, dep.licenseRisk];
        if (risks.includes('red')) return 'red';
        if (risks.includes('amber')) return 'amber';
        return 'green';
      }
      
      function applyFilters() {
        const term = (controls.search.value || '').toLowerCase();
        const directFilter = controls.direct.value;
        const runtimeFilter = controls.runtime.value;
        const hasVulns = controls.hasVulns.checked;
        const unusedOnly = controls.unusedOnly.checked;
        
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
          if (unusedOnly && dep.usage.status !== 'unused') return false;
          
          // License category filter
          const licenseCategory = getLicenseCategory(dep.license.license);
          if (licenseCategory === 'permissive' && !showPermissive) return false;
          if (licenseCategory === 'weakCopyleft' && !showWeakCopyleft) return false;
          if (licenseCategory === 'strongCopyleft' && !showStrongCopyleft) return false;
          if (licenseCategory === 'unknown' && !showUnknown) return false;
          
          return true;
        });
      }
      
      function sortDeps(deps) {
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
      
      function indicator(text, tone) {
        return '<div class="indicator"><span class="indicator-dot ' + tone + '"></span>' + escapeHtml(text) + '</div>';
      }
      
      function indicatorSeparator() {
        return '<div class="indicator-separator"></div>';
      }
      
      function renderKvItem(label, value, hint) {
        let html = '<div class="kv-item">';
        html += '<span class="kv-label">' + escapeHtml(label) + '</span>';
        html += '<span class="kv-value">' + escapeHtml(String(value)) + '</span>';
        if (hint) html += '<span class="kv-hint">' + escapeHtml(hint) + '</span>';
        html += '</div>';
        return html;
      }
      
      function renderPackageList(packages, maxShow) {
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
      
      function renderSection(title, desc, bodyHtml) {
        let html = '<div class="section">';
        html += '<div class="section-header">';
        html += '<span class="section-title">' + escapeHtml(title) + '</span>';
        if (desc) html += '<span class="section-desc">' + escapeHtml(desc) + '</span>';
        html += '</div>';
        html += bodyHtml;
        html += '</div>';
        return html;
      }
      
      function renderKvSection(title, desc, items) {
        return renderSection(title, desc, '<div class="kv-grid">' + items.join('') + '</div>');
      }
      
      function renderDep(dep) {
        const licenseText = dep.license.license || 'Unknown';
        const severity = highestSeverity(dep);
        const licenseCategory = getLicenseCategory(licenseText);
        const highestRisk = getHighestRisk(dep);
        
        const licenseCategoryDisplay = {
          permissive: { text: 'Permissive', class: 'green' },
          weakCopyleft: { text: 'Weak Copyleft', class: 'amber' },
          strongCopyleft: { text: 'Strong Copyleft', class: 'red' },
          unknown: { text: 'Unknown', class: 'gray' }
        };
        
        // Use new terminology: Dependency/Sub-Dependency instead of Direct/Transitive
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
          indicator(dep.usage.status, dep.usage.status === 'unused' ? 'red' : dep.usage.status === 'used' ? 'green' : 'gray')
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
        
        // Parents as package names, not keys
        const parentNames = (dep.parents || []).map(key => key.split('@')[0]);
        const installedBy = (dep.rootCauses || []).join(', ') || (dep.direct ? 'package.json' : 'Unknown');
        
        const overviewSection = renderKvSection('Overview', 'Dependency position and runtime classification', [
          renderKvItem('Type', depTypeText, dep.direct ? 'Listed in package.json' : 'Installed as a sub-dependency'),
          renderKvItem('Depth', dep.depth, 'How deep this package is in the dependency tree'),
          renderKvItem('Parents', parentNames.join(', ') || 'root', 'Packages that directly depend on this'),
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
          'Whether this package is actively used in your code',
          '<div class="kv-grid">' + renderKvItem('Status', dep.usage.status, dep.usage.reason) + '</div>'
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
        
        // Graph section with package lists
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
      
      function renderList() {
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
      [controls.search, controls.direct, controls.runtime, controls.sort, controls.hasVulns, controls.unusedOnly,
       controls.licensePermissive, controls.licenseWeakCopyleft, controls.licenseStrongCopyleft, controls.licenseUnknown
      ].forEach((ctrl) => {
        if (!ctrl) return;
        ctrl.addEventListener('input', renderList);
        ctrl.addEventListener('change', renderList);
      });
      
      renderList();
    })();
  </script>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function renderToolErrors(data: AggregatedData): string {
  const entries = Object.entries(data.toolErrors || {});
  if (!entries.length) return '';
  const list = entries.map(([tool, err]) => `<div><strong>${escapeHtml(tool)}:</strong> ${escapeHtml(err)}</div>`).join('');
  return `<div class="tool-errors"><strong>Some tools failed:</strong>${list}</div>`;
}
