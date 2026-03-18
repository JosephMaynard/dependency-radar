/**
 * Dependency Radar Report - Client-side rendering
 * TypeScript version of the report rendering logic
 */

import "./style.css";
import { buildCtaUrl } from "../src/cta";
import { initGraphView, type GraphViewHandle } from "./graphView";
import type {
  AggregatedData,
  DependencyRecord,
  ExecutionSignal,
  LicenseStatus,
  Severity,
} from "./types";

// In development, load sample data; in production, data is embedded
async function loadReportData(): Promise<AggregatedData> {
  const dataEl = document.getElementById("radar-data");
  if (dataEl && dataEl.textContent && dataEl.textContent.trim() !== "{}") {
    return JSON.parse(dataEl.textContent);
  }
  // Development mode: fetch sample data
  const response = await fetch("./sample-data.json");
  return response.json();
}

// License categorization
const LICENSE_CATEGORIES = {
  permissive: [
    "MIT",
    "ISC",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Apache-2.0",
    "Unlicense",
    "0BSD",
    "CC0-1.0",
    "BSD",
    "Apache",
    "Apache 2.0",
    "Apache License 2.0",
    "MIT License",
    "ISC License",
  ],
  weakCopyleft: [
    "LGPL-2.1",
    "LGPL-3.0",
    "LGPL-2.0",
    "LGPL",
    "MPL-2.0",
    "MPL-1.1",
    "MPL",
    "EPL-1.0",
    "EPL-2.0",
    "EPL",
  ],
  strongCopyleft: [
    "GPL-2.0",
    "GPL-3.0",
    "GPL",
    "AGPL-3.0",
    "AGPL",
    "GPL-2.0-only",
    "GPL-3.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-or-later",
  ],
} as const;

type LicenseCategory =
  | "permissive"
  | "weakCopyleft"
  | "strongCopyleft"
  | "unknown";

const EXECUTION_SIGNAL_LABELS: Record<ExecutionSignal, string> = {
  "network-access": "Accesses the network during install",
  "dynamic-exec": "Uses dynamic execution",
  "child-process": "Spawns child processes",
  encoding: "Uses encoding/decoding logic",
  obfuscated: "Contains obfuscated/minified install logic",
  "reads-env": "Reads environment variables",
  "reads-home": "Reads user home directory",
  "uses-ssh": "Uses SSH configuration/keys",
};

type SecuritySummary = {
  critical: number;
  high: number;
  moderate: number;
  low: number;
  highest: Severity | "none";
  risk: "green" | "amber" | "red";
};

type NormalizedSecurity = {
  summary: SecuritySummary;
  advisories?: DependencyRecord["security"]["advisories"];
};

// =============================================================================
// COLUMN CONFIGURATION - Single source of truth for all columns
// =============================================================================
// To add/remove/reorder columns, edit this array. The entire UI adapts automatically.
// Package name is always first and handled separately.

interface ColumnConfig {
  /** Unique identifier for the column (used for sorting state) */
  id: string;
  /** Display label shown in column header and mobile badge labels */
  label: string;
  /** Key used for sort state (may differ from id for grouped sorts) */
  sortKey: string;
  /** Extract display value from a dependency record */
  getValue: (dep: DependencyRecord) => string;
  /** Get color tone: "green" | "amber" | "red" | "gray" */
  getTone: (dep: DependencyRecord) => string;
  /** Custom sort comparator (ascending order). If not provided, uses string comparison of getValue */
  sortFn?: (a: DependencyRecord, b: DependencyRecord) => number;
}

// Helper functions for column config (defined here to avoid circular dependencies)
function getColumnLicenseCategory(
  license: string | undefined | null,
): LicenseCategory {
  if (!license) return "unknown";
  const normalized = license.toUpperCase();
  for (const [cat, licenses] of Object.entries(LICENSE_CATEGORIES)) {
    if (licenses.some((l) => normalized.includes(l.toUpperCase())))
      return cat as LicenseCategory;
  }
  return "unknown";
}

function getColumnScopeLabel(scope: string): string {
  if (scope === "runtime") return "Runtime";
  if (scope === "dev") return "Dev";
  if (scope === "optional") return "Optional";
  if (scope === "peer") return "Peer";
  return scope;
}

function getColumnCapitalize(str: string): string {
  if (!str) return str;
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function getColumnPrimaryLicense(dep: DependencyRecord): {
  value: string;
  isInferred: boolean;
} {
  const info = dep.compliance.license;
  const declared = info.declared?.valid ? info.declared.spdxId : undefined;
  const inferred = info.inferred?.spdxId;
  if (declared) return { value: declared, isInferred: false };
  if (inferred) return { value: inferred, isInferred: true };
  return { value: "Unknown", isInferred: false };
}

function getColumnNormalizeSecurity(dep: DependencyRecord): NormalizedSecurity {
  const security = (dep as DependencyRecord & { security?: any }).security;
  if (security?.summary) {
    return {
      summary: security.summary as SecuritySummary,
      advisories: security.advisories,
    };
  }
  if (security?.vulnerabilities) {
    const vulns = security.vulnerabilities;
    return {
      summary: {
        critical: Number(vulns.critical || 0),
        high: Number(vulns.high || 0),
        moderate: Number(vulns.moderate || 0),
        low: Number(vulns.low || 0),
        highest: (vulns.highest as Severity | "none") || "none",
        risk: (security.vulnRisk || security.risk || "green") as
          | "green"
          | "amber"
          | "red",
      },
      advisories: security.advisories,
    };
  }
  return {
    summary: {
      critical: 0,
      high: 0,
      moderate: 0,
      low: 0,
      highest: "none",
      risk: "green",
    },
    advisories: security?.advisories,
  };
}

function getColumnHighestSeverity(summary: SecuritySummary): Severity | "none" {
  return summary?.highest || "none";
}

function getColumnExecutionRiskTone(
  execution: DependencyRecord["execution"] | undefined,
): "green" | "amber" | "red" {
  if (!execution) return "green";
  return execution.risk || "green";
}

function getColumnExecutionRiskLabel(
  execution: DependencyRecord["execution"] | undefined,
): string {
  if (!execution) return "Low";
  return getColumnCapitalize(execution.risk || "low");
}

const licenseCategoryTone: Record<LicenseCategory, string> = {
  permissive: "green",
  weakCopyleft: "amber",
  strongCopyleft: "red",
  unknown: "gray",
};

const columnSeverityOrder: Record<Severity | "none", number> = {
  none: 0,
  low: 1,
  moderate: 2,
  high: 3,
  critical: 4,
};

/**
 * Column configuration array - THE SINGLE SOURCE OF TRUTH
 * Edit this array to add, remove, or reorder columns.
 * Both column headers and badge cards are generated from this config.
 */
const COLUMN_CONFIG: ColumnConfig[] = [
  {
    id: "type",
    label: "Type",
    sortKey: "type",
    getValue: (dep) => (dep.usage.direct ? "Dependency" : "Sub-Dependency"),
    getTone: (dep) => (dep.usage.direct ? "green" : "amber"),
    sortFn: (a, b) =>
      a.usage.direct === b.usage.direct ? 0 : a.usage.direct ? -1 : 1,
  },
  {
    id: "scope",
    label: "Scope",
    sortKey: "scope",
    getValue: (dep) => getColumnScopeLabel(dep.usage.scope),
    getTone: (dep) =>
      dep.usage.scope === "runtime"
        ? "green"
        : dep.usage.scope === "dev"
          ? "amber"
          : dep.usage.scope === "optional"
            ? "amber"
            : "gray",
    sortFn: (a, b) => a.usage.scope.localeCompare(b.usage.scope),
  },
  {
    id: "license",
    label: "License",
    sortKey: "license",
    getValue: (dep) => {
      const primary = getColumnPrimaryLicense(dep);
      const label = primary.isInferred
        ? `${primary.value} (inferred)`
        : primary.value;
      return dep.compliance.license.status === "mismatch"
        ? `${label} *`
        : label;
    },
    getTone: (dep) => {
      const primary = getColumnPrimaryLicense(dep);
      const category = getColumnLicenseCategory(primary.value);
      return licenseCategoryTone[category];
    },
    sortFn: (a, b) => {
      const aLicense = getColumnPrimaryLicense(a).value;
      const bLicense = getColumnPrimaryLicense(b).value;
      return aLicense.localeCompare(bLicense);
    },
  },
  {
    id: "vulns",
    label: "Vulnerabilities",
    sortKey: "severity",
    getValue: (dep) => {
      const severity = getColumnHighestSeverity(
        getColumnNormalizeSecurity(dep).summary,
      );
      return getColumnCapitalize(severity);
    },
    getTone: (dep) => getColumnNormalizeSecurity(dep).summary.risk,
    sortFn: (a, b) =>
      columnSeverityOrder[
        getColumnHighestSeverity(getColumnNormalizeSecurity(b).summary)
      ] -
      columnSeverityOrder[
        getColumnHighestSeverity(getColumnNormalizeSecurity(a).summary)
      ],
  },
  {
    id: "install",
    label: "Install",
    sortKey: "install",
    getValue: (dep) => getColumnExecutionRiskLabel(dep.execution),
    getTone: (dep) => getColumnExecutionRiskTone(dep.execution),
    sortFn: (a, b) => {
      const riskOrder = { green: 0, amber: 1, red: 2 };
      const aRisk = getColumnExecutionRiskTone(a.execution);
      const bRisk = getColumnExecutionRiskTone(b.execution);
      return riskOrder[aRisk] - riskOrder[bRisk];
    },
  },
];

// Export column count for CSS variable
const COLUMN_COUNT = COLUMN_CONFIG.length;

function getLicenseCategory(
  license: string | undefined | null,
): LicenseCategory {
  if (!license) return "unknown";
  const normalized = license.toUpperCase();
  for (const [cat, licenses] of Object.entries(LICENSE_CATEGORIES)) {
    if (licenses.some((l) => normalized.includes(l.toUpperCase())))
      return cat as LicenseCategory;
  }
  return "unknown";
}

function resolvePrimaryLicense(dep: DependencyRecord): {
  value: string;
  isInferred: boolean;
} {
  const info = dep.compliance.license;
  const declared = info.declared?.valid ? info.declared.spdxId : undefined;
  const inferred = info.inferred?.spdxId;
  if (declared) return { value: declared, isInferred: false };
  if (inferred) return { value: inferred, isInferred: true };
  return { value: "Unknown", isInferred: false };
}

function formatLicenseStatus(status: LicenseStatus): string {
  switch (status) {
    case "declared-only":
      return "Declared";
    case "inferred-only":
      return "Inferred";
    case "match":
      return "Declared + Inferred (match)";
    case "mismatch":
      return "Declared + Inferred (mismatch)";
    case "invalid-spdx":
      return "Invalid SPDX";
    default:
      return "Unknown";
  }
}

const severityOrder: Record<Severity | "none", number> = {
  none: 0,
  low: 1,
  moderate: 2,
  high: 3,
  critical: 4,
};

function normalizeSecurity(dep: DependencyRecord): NormalizedSecurity {
  const security = (dep as DependencyRecord & { security?: any }).security;
  if (security?.summary) {
    return {
      summary: security.summary as SecuritySummary,
      advisories: security.advisories,
    };
  }
  if (security?.vulnerabilities) {
    const vulns = security.vulnerabilities;
    return {
      summary: {
        critical: Number(vulns.critical || 0),
        high: Number(vulns.high || 0),
        moderate: Number(vulns.moderate || 0),
        low: Number(vulns.low || 0),
        highest: (vulns.highest as Severity | "none") || "none",
        risk: (security.vulnRisk || security.risk || "green") as
          | "green"
          | "amber"
          | "red",
      },
      advisories: security.advisories,
    };
  }
  return {
    summary: {
      critical: 0,
      high: 0,
      moderate: 0,
      low: 0,
      highest: "none",
      risk: "green",
    },
    advisories: security?.advisories,
  };
}

function highestSeverity(summary: SecuritySummary): Severity | "none" {
  return summary?.highest || "none";
}

function yesNo(flag: boolean | undefined): string {
  return flag ? "Yes" : "No";
}

function escapeHtml(str: string | null | undefined): string {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function getHighestRisk(
  summary: SecuritySummary,
  licenseRisk: "green" | "amber" | "red",
): "red" | "amber" | "green" {
  const risks = [summary.risk, licenseRisk];
  if (risks.includes("red")) return "red";
  if (risks.includes("amber")) return "amber";
  return "green";
}

function scopeLabel(scope: string): string {
  if (scope === "runtime") return "Runtime";
  if (scope === "dev") return "Dev";
  if (scope === "optional") return "Optional";
  if (scope === "peer") return "Peer";
  return scope;
}

function capitalize(str: string): string {
  if (!str) return str;
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function titleCaseValue(value: string): string {
  return value
    .split(/[\s-_]+/)
    .map((part) => (part ? capitalize(part) : part))
    .join(" ");
}

function tsTypesLabel(tsTypes: DependencyRecord["usage"]["tsTypes"]): string {
  if (tsTypes === "bundled") return "Bundled";
  if (tsTypes === "definitelyTyped") return "DefinitelyTyped";
  if (tsTypes === "none") return "None";
  return "Unknown";
}

function runtimeImpactLabel(
  impact: DependencyRecord["usage"]["runtimeImpact"] | undefined,
): string {
  if (!impact) return "";
  return titleCaseValue(impact);
}

function outdatedStatusLabel(
  status: DependencyRecord["upgrade"]["outdatedStatus"] | undefined,
): string {
  if (!status) return "Not reported";
  if (status === "unknown") return "Unknown";
  return titleCaseValue(status);
}

function badgeCard(label: string, value: string, tone: string): string {
  return (
    '<div class="badge-card ' +
    tone +
    '">' +
    '<span class="badge-label">' +
    escapeHtml(label) +
    "</span>" +
    '<span class="badge-value">' +
    escapeHtml(value) +
    "</span>" +
    "</div>"
  );
}

/**
 * Render badges from COLUMN_CONFIG for a dependency
 * This is the config-driven replacement for the hardcoded badges array
 */
function renderBadgesFromConfig(dep: DependencyRecord): string {
  return COLUMN_CONFIG.map((col) =>
    badgeCard(col.label, col.getValue(dep), col.getTone(dep)),
  ).join("");
}

/**
 * Render column headers for the sticky filter bar
 * Returns HTML string for the column headers row (only for badge columns, not package name)
 */
function renderColumnHeaders(
  sortColumn: string,
  sortAscending: boolean,
): string {
  // Only render headers for badge columns - these align with the dep-indicators grid
  const headers = COLUMN_CONFIG.map((col) =>
    renderSingleColumnHeader(col.sortKey, col.label, sortColumn, sortAscending),
  ).join("");

  return (
    '<div class="column-headers" style="--column-count: ' +
    COLUMN_COUNT +
    '">' +
    headers +
    "</div>"
  );
}

function renderSingleColumnHeader(
  sortKey: string,
  label: string,
  currentSortColumn: string,
  sortAscending: boolean,
): string {
  const isActive = currentSortColumn === sortKey;
  const sortIndicator = isActive ? (sortAscending ? " ▲" : " ▼") : "";
  const activeClass = isActive ? " sorted" : "";
  const directionClass = isActive
    ? sortAscending
      ? " sorted-asc"
      : " sorted-desc"
    : "";

  return (
    '<button type="button" class="column-header' +
    activeClass +
    directionClass +
    '" data-sort="' +
    escapeHtml(sortKey) +
    '">' +
    '<span class="column-header-label">' +
    escapeHtml(label) +
    "</span>" +
    '<span class="sort-indicator">' +
    sortIndicator +
    "</span>" +
    "</button>"
  );
}

function renderKvItem(
  label: string,
  value: string | number,
  hint?: string,
): string {
  let html = '<div class="kv-item">';
  html += '<span class="kv-label">' + escapeHtml(label) + "</span>";
  html += '<span class="kv-value">' + escapeHtml(String(value)) + "</span>";
  if (hint) html += '<span class="kv-hint">' + escapeHtml(hint) + "</span>";
  html += "</div>";
  return html;
}

function renderRiskValue(
  value: string | number,
  risk: "green" | "amber" | "red",
): string {
  return (
    '<span class="kv-value risk-value"><span class="risk-dot ' +
    risk +
    '"></span>' +
    escapeHtml(String(value)) +
    "</span>"
  );
}

function renderKvItemHtml(
  label: string,
  valueHtml: string,
  hint?: string,
): string {
  let html = '<div class="kv-item">';
  html += '<span class="kv-label">' + escapeHtml(label) + "</span>";
  html += valueHtml;
  if (hint) html += '<span class="kv-hint">' + escapeHtml(hint) + "</span>";
  html += "</div>";
  return html;
}

function renderPackageList(
  packages: string[] | undefined,
  maxShow: number,
): string {
  if (!packages || packages.length === 0)
    return '<span class="kv-value">None</span>';
  const shown = packages.slice(0, maxShow);
  const remaining = packages.length - maxShow;
  let html = '<div class="package-list">';
  shown.forEach((pkg) => {
    html += '<span class="package-tag">' + escapeHtml(pkg) + "</span>";
  });
  if (remaining > 0) {
    html += '<span class="package-tag">+' + remaining + " more</span>";
  }
  html += "</div>";
  return html;
}

function renderDependencyIdList(
  ids: string[] | undefined,
  maxShow: number,
  linkableKeys: Set<string>,
  keysByName?: DepKeysByNameIndex,
): string {
  if (!ids || ids.length === 0) return '<span class="kv-value">None</span>';
  const shown = ids.slice(0, maxShow);
  const remaining = ids.length - maxShow;
  let html = '<div class="package-list">';
  shown.forEach((id) => {
    const resolvedDepKey = resolveDepLinkTarget(id, linkableKeys, keysByName);
    if (!resolvedDepKey) {
      html += '<span class="package-tag">' + escapeHtml(id) + "</span>";
      return;
    }
    html +=
      '<a class="package-tag package-tag-link root-package-link" href="#' +
      escapeHtml(getDepDomId(resolvedDepKey)) +
      '" data-dep-key="' +
      escapeHtml(resolvedDepKey) +
      '" aria-label="Jump to dependency ' +
      escapeHtml(resolvedDepKey) +
      '">' +
      escapeHtml(id) +
      "</a>";
  });
  if (remaining > 0) {
    html += '<span class="package-tag">+' + remaining + " more</span>";
  }
  html += "</div>";
  return html;
}

function getDepKey(name: string, version: string): string {
  return name + "@" + version;
}

type DepKeysByNameIndex = Map<string, string[]>;
const depKeysByNameCache = new WeakMap<Set<string>, DepKeysByNameIndex>();

function parseDepKey(depKey: string): { name: string; version: string } | null {
  const npmAliasAt = depKey.lastIndexOf("@npm:");
  if (npmAliasAt > 0) {
    return {
      name: depKey.slice(0, npmAliasAt),
      version: depKey.slice(npmAliasAt + 1),
    };
  }
  const lastAt = depKey.lastIndexOf("@");
  if (lastAt <= 0) return null;
  return {
    name: depKey.slice(0, lastAt),
    version: depKey.slice(lastAt + 1),
  };
}

function getDepDomId(depKey: string): string {
  return `dep-${depKey}`;
}

function getDepKeysByNameIndex(linkableKeys: Set<string>): DepKeysByNameIndex {
  const cached = depKeysByNameCache.get(linkableKeys);
  if (cached) return cached;
  const index: DepKeysByNameIndex = new Map<string, string[]>();
  linkableKeys.forEach((candidate) => {
    const parsed = parseDepKey(candidate);
    if (!parsed) return;
    const keys = index.get(parsed.name) || [];
    keys.push(candidate);
    index.set(parsed.name, keys);
  });
  depKeysByNameCache.set(linkableKeys, index);
  return index;
}

function resolveDepKeyByNameFromSet(
  name: string,
  linkableKeys: Set<string>,
  keysByName?: DepKeysByNameIndex,
): string | null {
  const nameIndex = keysByName || getDepKeysByNameIndex(linkableKeys);
  const candidates = (nameIndex.get(name) || []).filter((candidate) =>
    linkableKeys.has(candidate),
  );
  if (candidates.length === 1) return candidates[0];
  return null;
}

function resolveDepLinkTarget(
  depKey: string,
  linkableKeys: Set<string>,
  keysByName?: DepKeysByNameIndex,
): string | null {
  if (linkableKeys.has(depKey)) return depKey;
  const parsed = parseDepKey(depKey);
  if (!parsed)
    return resolveDepKeyByNameFromSet(depKey, linkableKeys, keysByName);

  if (parsed.version.startsWith("npm:")) {
    const aliasedTarget = parsed.version.slice("npm:".length);
    const npmAliasKey =
      parsed.name +
      (aliasedTarget.startsWith("@") ? aliasedTarget : "@" + aliasedTarget);
    if (linkableKeys.has(npmAliasKey)) return npmAliasKey;
  }
  return resolveDepKeyByNameFromSet(parsed.name, linkableKeys, keysByName);
}

function renderRootPackageList(
  packages: Array<{ name: string; version: string } | string> | undefined,
  maxShow: number,
  linkableKeys: Set<string>,
  keysByName?: DepKeysByNameIndex,
): string {
  if (!packages || packages.length === 0)
    return '<span class="kv-value">None</span>';
  const shown = packages.slice(0, maxShow);
  const remaining = packages.length - maxShow;
  let html = '<div class="package-list">';
  shown.forEach((pkg) => {
    if (typeof pkg === "string") {
      const resolvedDepKey = resolveDepLinkTarget(
        pkg,
        linkableKeys,
        keysByName,
      );
      if (!resolvedDepKey) {
        html += '<span class="package-tag">' + escapeHtml(pkg) + "</span>";
        return;
      }
      html +=
        '<a class="package-tag package-tag-link root-package-link" href="#' +
        escapeHtml(getDepDomId(resolvedDepKey)) +
        '" data-dep-key="' +
        escapeHtml(resolvedDepKey) +
        '" aria-label="Jump to dependency ' +
        escapeHtml(resolvedDepKey) +
        '">' +
        escapeHtml(pkg) +
        "</a>";
      return;
    }
    const depKey = getDepKey(pkg.name, pkg.version);
    const label = pkg.name + "@" + pkg.version;
    const resolvedDepKey = resolveDepLinkTarget(
      depKey,
      linkableKeys,
      keysByName,
    );
    if (!resolvedDepKey) {
      html += '<span class="package-tag">' + escapeHtml(label) + "</span>";
      return;
    }
    html +=
      '<a class="package-tag package-tag-link root-package-link" href="#' +
      escapeHtml(getDepDomId(resolvedDepKey)) +
      '" data-dep-key="' +
      escapeHtml(resolvedDepKey) +
      '" aria-label="Jump to dependency ' +
      escapeHtml(resolvedDepKey) +
      '">' +
      escapeHtml(label) +
      "</a>";
  });
  if (remaining > 0) {
    html += '<span class="package-tag">+' + remaining + " more</span>";
  }
  html += "</div>";
  return html;
}

function renderLoadingPlaceholder(): string {
  // Minimal placeholder to show intentional loading while details render lazily.
  return [
    '<div class="dep-loading" role="presentation">',
    '<div class="dep-loading-bar"></div>',
    "</div>",
  ].join("");
}

function renderDetailList(
  title: string,
  items: string[] | undefined,
  maxShow: number,
  className?: string,
): string {
  if (!items || items.length === 0) return "";
  const shown = items.slice(0, maxShow);
  const remaining = items.length - maxShow;
  let html = '<div class="detail-list">';
  html += '<div class="detail-title">' + escapeHtml(title) + "</div>";
  html += '<ul class="detail-items' + (className ? " " + className : "") + '">';
  shown.forEach((item) => {
    html += '<li class="detail-item">' + escapeHtml(item) + "</li>";
  });
  if (remaining > 0) {
    html += '<li class="detail-item muted">+' + remaining + " more</li>";
  }
  html += "</ul></div>";
  return html;
}

function renderDeclaredDependencies(
  dep: DependencyRecord,
  linkableKeys: Set<string>,
  keysByName?: DepKeysByNameIndex,
): string {
  const subDeps = dep.graph.subDeps;
  if (!subDeps) return "";
  const groups: Array<{
    title: string;
    key: keyof NonNullable<DependencyRecord["graph"]["subDeps"]>;
  }> = [
    { title: "Dependencies", key: "dep" },
    { title: "Optional", key: "opt" },
    { title: "Peer", key: "peer" },
    { title: "Dev Dependencies", key: "dev" },
  ];

  let total = 0;
  let installed = 0;
  for (const group of groups) {
    const items = subDeps[group.key];
    if (!items) continue;
    for (const entry of Object.values(items)) {
      total += 1;
      if (entry[1]) installed += 1;
    }
  }
  if (total === 0) return "";
  const missing = total - installed;
  const summary =
    '<div class="declared-summary">Total: ' +
    total +
    " • Installed: " +
    installed +
    " • Not installed: " +
    missing +
    "</div>";

  const sections = groups
    .map((group) => {
      const items = subDeps[group.key];
      if (!items || Object.keys(items).length === 0) return "";
      let groupTotal = 0;
      let groupInstalled = 0;
      const rows = Object.entries(items)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([name, [range, resolvedId]]) => {
          groupTotal += 1;
          if (resolvedId) groupInstalled += 1;
          const nameCell =
            '<div class="declared-name">' + escapeHtml(name) + "</div>";
          const rangeCell =
            '<div class="declared-range">' + escapeHtml(range) + "</div>";
          const statusCell = resolvedId
            ? renderInstalledStatus(resolvedId, linkableKeys, keysByName)
            : '<span class="status-pill missing">Not installed</span>';
          return (
            '<div class="declared-row">' +
            nameCell +
            rangeCell +
            statusCell +
            "</div>"
          );
        });
      const installedText = groupInstalled + " of " + groupTotal + " installed";
      return [
        '<details class="declared-group">',
        '<summary class="declared-group-summary"><span class="expand-icon" aria-hidden="true"></span><span class="declared-group-title">' +
          escapeHtml(group.title) +
          ' <span class="declared-count">(' +
          installedText +
          ")</span></span></summary>",
        '<div class="declared-table">' + rows.join("") + "</div>",
        "</details>",
      ].join("");
    })
    .filter(Boolean);

  const body =
    summary + '<div class="declared-deps">' + sections.join("") + "</div>";
  return renderSection(
    "Declared Dependencies",
    "Dependencies declared by this package",
    body,
  );
}

function renderInstalledStatus(
  depKey: string,
  linkableKeys: Set<string>,
  keysByName?: DepKeysByNameIndex,
): string {
  const resolvedDepKey = resolveDepLinkTarget(depKey, linkableKeys, keysByName);
  if (!resolvedDepKey)
    return '<span class="status-pill installed">Installed</span>';
  return (
    '<a class="status-pill installed root-package-link" href="#' +
    escapeHtml(getDepDomId(resolvedDepKey)) +
    '" data-dep-key="' +
    escapeHtml(resolvedDepKey) +
    '" aria-label="Jump to dependency ' +
    escapeHtml(resolvedDepKey) +
    '">' +
    "Installed" +
    "</a>"
  );
}

function renderSection(
  title: string,
  desc: string | undefined,
  bodyHtml: string,
): string {
  let html = '<div class="section">';
  html += '<div class="section-header">';
  html += '<span class="section-title">' + escapeHtml(title) + "</span>";
  if (desc)
    html += '<span class="section-desc">' + escapeHtml(desc) + "</span>";
  html += "</div>";
  html += bodyHtml;
  html += "</div>";
  return html;
}

function renderSubsection(
  title: string,
  bodyHtml: string,
  desc?: string,
  className?: string,
): string {
  let html =
    '<div class="subsection' + (className ? " " + className : "") + '">';
  html += '<div class="subsection-header">';
  html += '<span class="subsection-title">' + escapeHtml(title) + "</span>";
  if (desc)
    html += '<span class="subsection-desc">' + escapeHtml(desc) + "</span>";
  html += "</div>";
  html += bodyHtml;
  html += "</div>";
  return html;
}

function toneToString(tone?: "red" | "amber" | "green"): string {
  if (tone === "red") return "High";
  if (tone === "amber") return "Medium";
  return "Low";
}

function renderExecutionSection(
  execution: NonNullable<DependencyRecord["execution"]>,
): string {
  const items: string[] = [
    renderKvItemHtml(
      "Execution risk",
      renderRiskValue(toneToString(execution.risk), execution.risk),
    ),
  ];

  if (execution.native) {
    items.push(renderKvItem("Native build tooling detected (native)", "Yes"));
  }

  if (execution.scripts?.hooks?.length) {
    items.push(
      renderKvItemHtml(
        "Lifecycle hooks",
        renderPackageList(execution.scripts.hooks, 6),
      ),
    );
  }

  if (typeof execution.scripts?.complexity === "number") {
    items.push(
      renderKvItem(
        "Heuristic complexity",
        "Script complexity: " + execution.scripts.complexity + " (complexity)",
      ),
    );
  }

  if (execution.scripts?.signals?.length) {
    const labels = execution.scripts.signals.map(
      (signal) => `${EXECUTION_SIGNAL_LABELS[signal]} (${signal})`,
    );
    items.push(
      renderKvItemHtml("Install-time signals", renderPackageList(labels, 6)),
    );
  }

  const note =
    '<div class="section-note">Install-time behaviour signals detected. These describe code that runs automatically during install and may warrant review in security-sensitive environments.</div>';

  return renderSubsection(
    "Install-time execution behaviour",
    note + '<div class="kv-grid">' + items.join("") + "</div>",
  );
}

type LinkSet = {
  npm?: string;
  repository?: string;
  homepage?: string;
  issues?: string;
};

function normalizeRepositoryUrl(
  rawUrl: string | undefined,
): string | undefined {
  if (!rawUrl) return undefined;
  const trimmed = rawUrl.trim();
  if (!trimmed) return undefined;

  const stripGitSuffix = (value: string): string =>
    value.replace(/\.git$/i, "");

  if (/^https?:\/\//i.test(trimmed)) return stripGitSuffix(trimmed);
  if (/^git\+https?:\/\//i.test(trimmed)) {
    return stripGitSuffix(trimmed.replace(/^git\+/, ""));
  }
  if (/^git:\/\/github\.com\//i.test(trimmed)) {
    return stripGitSuffix(trimmed.replace(/^git:\/\//i, "https://"));
  }
  if (/^github:/i.test(trimmed)) {
    const suffix = trimmed.slice("github:".length).replace(/^\/+/, "");
    return suffix ? `https://github.com/${stripGitSuffix(suffix)}` : undefined;
  }
  if (/^git@github\.com:/i.test(trimmed)) {
    const suffix = trimmed.slice("git@github.com:".length);
    return suffix ? `https://github.com/${stripGitSuffix(suffix)}` : undefined;
  }
  if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(trimmed)) {
    return `https://github.com/${stripGitSuffix(trimmed)}`;
  }
  return undefined;
}

function buildGithubFileUrl(
  repositoryUrl: string | undefined,
  filePath: "package.json" | "LICENSE",
): string | undefined {
  const normalizedRepoUrl = normalizeRepositoryUrl(repositoryUrl);
  if (!normalizedRepoUrl) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(normalizedRepoUrl);
  } catch {
    return undefined;
  }
  if (parsed.hostname.toLowerCase() !== "github.com") return undefined;
  const parts = parsed.pathname.split("/").filter(Boolean);
  if (parts.length < 2) return undefined;
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/i, "");
  if (!owner || !repo) return undefined;
  return `https://github.com/${owner}/${repo}/blob/HEAD/${filePath}`;
}

function appendGithubFileLink(
  value: string,
  fileUrl: string | undefined,
): string {
  if (!fileUrl) return escapeHtml(value);
  return (
    escapeHtml(value) +
    ' <a class="kv-inline-link" href="' +
    escapeHtml(fileUrl) +
    '" target="_blank" rel="noopener noreferrer">GitHub' +
    '<svg class="kv-inline-link-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">' +
    '<path d="M7 17 17 7"/><path d="M9 7h8v8"/>' +
    "</svg></a>"
  );
}

function resolveLinks(dep: DependencyRecord): LinkSet {
  const pkgLinks =
    dep.package?.links || ({} as DependencyRecord["package"]["links"]);
  const legacyLinks =
    (dep as DependencyRecord & { links?: Record<string, string> }).links || {};
  const normalizedRepository = normalizeRepositoryUrl(
    pkgLinks.repository || legacyLinks.repository || legacyLinks.repo,
  );
  return {
    npm: pkgLinks.npm || legacyLinks.npm,
    repository:
      normalizedRepository ||
      pkgLinks.repository ||
      legacyLinks.repository ||
      legacyLinks.repo,
    homepage: pkgLinks.homepage || legacyLinks.homepage,
    issues:
      pkgLinks.bugs ||
      (pkgLinks as { issues?: string }).issues ||
      legacyLinks.bugs ||
      legacyLinks.issues,
  };
}

function renderPackageLinks(links: LinkSet): string {
  const icons = {
    npm: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M0 7.334v8h6.666v1.332H12v-1.332h12v-8H0zm6.666 6.664H5.334v-4H3.999v4H1.335V8.667h5.331v5.331zm4 0v1.336H8.001V8.667h5.334v5.332h-2.669v-.001zm12.001 0h-1.33v-4h-1.336v4h-1.335v-4h-1.33v4h-2.671V8.667h8.002v5.331zM10.665 10H12v2.667h-1.335V10z"/></svg>',
    repo: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>',
    bugs: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    homepage:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>',
  };

  if (!links.npm && !links.repository && !links.homepage && !links.issues) {
    return "";
  }
  let html = '<div class="package-links">';
  if (links.npm) {
    html +=
      '<a href="' +
      escapeHtml(links.npm) +
      '" target="_blank" rel="noopener" class="package-link">' +
      icons.npm +
      "npm</a>";
  }

  if (links.repository) {
    html +=
      '<a href="' +
      escapeHtml(links.repository) +
      '" target="_blank" rel="noopener" class="package-link">' +
      icons.repo +
      "Repository</a>";
  }

  if (links.homepage) {
    html +=
      '<a href="' +
      escapeHtml(links.homepage) +
      '" target="_blank" rel="noopener" class="package-link">' +
      icons.homepage +
      "Homepage</a>";
  }

  if (links.issues) {
    html +=
      '<a href="' +
      escapeHtml(links.issues) +
      '" target="_blank" rel="noopener" class="package-link">' +
      icons.bugs +
      "Issues</a>";
  }

  html += "</div>";
  return html;
}

function renderAdvisoriesTable(
  advisories: DependencyRecord["security"]["advisories"] | undefined,
): string {
  if (!advisories || advisories.length === 0) {
    return "";
  }
  let html = '<table class="vuln-table"><thead><tr>';
  html +=
    "<th>Title</th><th>Severity</th><th>Affected range</th><th>Fix available</th><th>Reference</th>";
  html += "</tr></thead><tbody>";
  advisories.forEach((adv) => {
    const advisoryCell = escapeHtml(adv.title);
    const referenceCell = adv.url
      ? '<a href="' +
        escapeHtml(adv.url) +
        '" target="_blank" rel="noopener">Link</a>'
      : "";
    html += '<tr data-severity="' + escapeHtml(adv.severity) + '">';
    html += '<td data-label="Title">' + advisoryCell + "</td>";
    html +=
      '<td data-label="Severity">' +
      escapeHtml(capitalize(adv.severity)) +
      "</td>";
    html +=
      '<td data-label="Affected range">' +
      escapeHtml(adv.vulnerableRange) +
      "</td>";
    html +=
      '<td data-label="Fix available">' +
      escapeHtml(adv.fixAvailable ? "Yes" : "No") +
      "</td>";
    html += '<td data-label="Reference">' + referenceCell + "</td>";
    html += "</tr>";
  });
  html += "</tbody></table>";
  return html;
}

function renderDep(dep: DependencyRecord): string {
  const normalizedSecurity = normalizeSecurity(dep);
  const securitySummary = normalizedSecurity.summary;
  const highestRisk = getHighestRisk(
    securitySummary,
    dep.compliance.licenseRisk,
  );
  const depKey = getDepKey(dep.package.name, dep.package.version);
  const domId = getDepDomId(depKey);

  // Use config-driven badge rendering
  const badges = renderBadgesFromConfig(dep);

  const summary = [
    '<summary class="dep-summary">',
    '<span class="expand-icon" aria-hidden="true"></span>',
    '<span class="dep-name">' +
      escapeHtml(dep.package.name) +
      '<span class="dep-version">@' +
      escapeHtml(dep.package.version) +
      "</span></span>",
    '<div class="dep-indicators" style="--column-count: ' + COLUMN_COUNT + '">',
    badges,
    "</div>",
    "</summary>",
  ].join("");

  return [
    '<details class="dep-card" data-risk="' +
      highestRisk +
      '" data-dep-key="' +
      escapeHtml(depKey) +
      '" id="' +
      escapeHtml(domId) +
      '">',
    summary,
    '<div class="dep-details" data-rendered="false"></div>',
    "</details>",
  ].join("");
}

function renderDepDetails(
  dep: DependencyRecord,
  linkableKeys: Set<string>,
  keysByName?: DepKeysByNameIndex,
): string {
  const normalizedSecurity = normalizeSecurity(dep);
  const securitySummary = normalizedSecurity.summary;
  const primaryLicense = resolvePrimaryLicense(dep);
  const licenseText = primaryLicense.isInferred
    ? `${primaryLicense.value} (inferred)`
    : primaryLicense.value;
  const links = resolveLinks(dep);
  const rawJson = JSON.stringify(dep, null, 2);

  const microLines: string[] = [
    dep.usage.direct ? "Direct dependency" : "Indirect dependency (transitive)",
    "Scope: " + scopeLabel(dep.usage.scope),
  ];
  if (dep.package.description) {
    microLines.unshift("Description: " + dep.package.description);
  }
  if (dep.usage.origins.workspaces?.length) {
    microLines.push(
      "Used in " + dep.usage.origins.workspaces.length + " workspaces",
    );
  }
  if (dep.usage.importUsage) {
    microLines.push(
      "Imported in " + dep.usage.importUsage.fileCount + " project files",
    );
  }
  if (dep.usage.introduction) {
    microLines.push("Introduced by: " + titleCaseValue(dep.usage.introduction));
  }
  if (microLines.length < 3) {
    microLines.push("Dependency depth: " + dep.usage.depth);
  }
  const microSummaryHtml =
    '<div class="micro-summary">' +
    microLines
      .slice(0, 5)
      .map((line) => '<div class="micro-line">' + escapeHtml(line) + "</div>")
      .join("") +
    "</div>";

  const workspaceListHtml = dep.usage.origins.workspaces?.length
    ? '<div class="micro-sublist"><div class="micro-subtitle">Workspaces</div>' +
      renderPackageList(dep.usage.origins.workspaces, 8) +
      "</div>"
    : "";

  const keyContextItems = [
    dep.usage.runtimeImpact
      ? renderKvItem(
          "Runtime impact",
          runtimeImpactLabel(dep.usage.runtimeImpact),
        )
      : "",
    renderKvItem("Dependency depth", dep.usage.depth),
    renderKvItemHtml(
      "Introduced via root packages",
      renderRootPackageList(
        dep.usage.origins.topRootPackages,
        8,
        linkableKeys,
        keysByName,
      ),
    ),
    renderKvItem("Direct roots", dep.usage.origins.rootPackageCount),
    renderKvItemHtml(
      "Direct parents",
      renderDependencyIdList(
        dep.usage.origins.topParentPackages,
        8,
        linkableKeys,
        keysByName,
      ),
    ),
    renderKvItem(
      "Direct parents count",
      dep.usage.origins.parentPackageCount ?? 0,
    ),
    renderKvItem("TypeScript types", tsTypesLabel(dep.usage.tsTypes)),
  ].filter(Boolean);

  const keyContextHtml =
    '<div class="section-block"><div class="block-title">Key context</div><div class="kv-grid kv-grid-tight">' +
    keyContextItems.join("") +
    "</div></div>";
  const importTopFilesHtml = renderDetailList(
    "Top import locations",
    dep.usage.importUsage?.topFiles,
    5,
    "mono",
  );

  const overviewSection = renderSection(
    "Overview",
    "Summary and key context",
    microSummaryHtml + workspaceListHtml + keyContextHtml + importTopFilesHtml,
  );

  const licenseInfo = dep.compliance.license;
  const declaredSpdxFileUrl = buildGithubFileUrl(
    links.repository,
    "package.json",
  );
  const inferredLicenseFileUrl = buildGithubFileUrl(
    links.repository,
    "LICENSE",
  );
  const licenseDetails: string[] = [
    renderKvItemHtml(
      "Primary license",
      renderRiskValue(licenseText, dep.compliance.licenseRisk),
    ),
    renderKvItem("Status", formatLicenseStatus(licenseInfo.status)),
  ];
  if (licenseInfo.declared) {
    const declaredMeta = [
      licenseInfo.declared.valid ? "valid" : "invalid",
      licenseInfo.declared.expression ? "expression" : undefined,
      licenseInfo.declared.deprecated ? "deprecated" : undefined,
    ]
      .filter(Boolean)
      .join(", ");
    const exceptionLabel = licenseInfo.exception?.id
      ? ` WITH ${licenseInfo.exception.id}`
      : "";
    licenseDetails.push(
      renderKvItemHtml(
        "Declared SPDX in package.json",
        '<span class="kv-value">' +
          appendGithubFileLink(
            `${licenseInfo.declared.spdxId}${exceptionLabel}${declaredMeta ? ` (${declaredMeta})` : ""}`,
            declaredSpdxFileUrl,
          ) +
          "</span>",
      ),
    );
  }
  if (licenseInfo.inferred) {
    licenseDetails.push(
      renderKvItemHtml(
        "Inferred from LICENSE file",
        '<span class="kv-value">' +
          appendGithubFileLink(
            `${licenseInfo.inferred.spdxId} (${licenseInfo.inferred.confidence})`,
            inferredLicenseFileUrl,
          ) +
          "</span>",
      ),
    );
  }
  if (licenseInfo.status === "mismatch") {
    licenseDetails.push(
      renderKvItem("Mismatch", "Declared SPDX and LICENSE text do not match"),
    );
  }
  if (licenseInfo.status === "invalid-spdx") {
    licenseDetails.push(
      renderKvItem(
        "Invalid SPDX",
        "Package.json license is not a valid SPDX identifier or expression",
      ),
    );
  }
  const licenseBlock = renderSubsection(
    "License",
    '<div class="kv-grid">' + licenseDetails.join("") + "</div>",
  );

  const vulnTotal =
    securitySummary.critical +
    securitySummary.high +
    securitySummary.moderate +
    securitySummary.low;
  const vulnSummaryItems = [
    renderKvItemHtml(
      "Known vulnerabilities",
      renderRiskValue(
        vulnTotal === 0 ? "None" : String(vulnTotal),
        securitySummary.risk,
      ),
    ),
    renderKvItem(
      "Highest severity",
      securitySummary.highest === "none"
        ? "None"
        : titleCaseValue(securitySummary.highest),
    ),
  ];
  const vulnBreakdown =
    vulnTotal > 0
      ? '<div class="kv-grid kv-grid-tight">' +
        [
          renderKvItem("Critical", securitySummary.critical),
          renderKvItem("High", securitySummary.high),
          renderKvItem("Moderate", securitySummary.moderate),
          renderKvItem("Low", securitySummary.low),
        ].join("") +
        "</div>"
      : "";
  const advisoriesTable = renderAdvisoriesTable(normalizedSecurity.advisories);
  const vulnBody = [
    '<div class="section-note">Based on npm audit findings (known disclosed issues).</div>',
    '<div class="kv-grid">' + vulnSummaryItems.join("") + "</div>",
    vulnBreakdown ? '<div class="subtle-divider"></div>' + vulnBreakdown : "",
    advisoriesTable
      ? '<div class="subtle-divider"></div>' + advisoriesTable
      : "",
  ].join("");
  const vulnBlock = renderSubsection(
    "VULNERABILITIES",
    vulnBody,
    "Known security issues from npm audit",
    "vuln-block",
  );

  const executionBlock = dep.execution
    ? renderExecutionSection(dep.execution)
    : "";

  const riskSection = renderSection(
    "Risk & Compliance",
    "License, vulnerabilities, and install-time execution signals",
    licenseBlock + vulnBlock + executionBlock,
  );

  const currencyItems = [
    renderKvItem(
      "Outdated status",
      outdatedStatusLabel(dep.upgrade.outdatedStatus),
    ),
  ];
  if (dep.upgrade.latestVersion) {
    currencyItems.push(
      renderKvItem("Latest version", dep.upgrade.latestVersion),
    );
  }
  const currencyBlock = renderSubsection(
    "Version",
    '<div class="section-note">Based on npm outdated findings.</div>' +
      '<div class="kv-grid">' +
      currencyItems.join("") +
      "</div>",
  );

  const deprecatedBlock = dep.package.deprecated
    ? renderSubsection(
        "Deprecated",
        '<div class="kv-grid">' +
          renderKvItem("Deprecated", "Yes", "Declared by the package author.") +
          "</div>",
        undefined,
        "warning",
      )
    : "";

  const constraintItems = [
    renderKvItem("Node engine constraint", dep.upgrade.nodeEngine || "Any"),
  ];
  if (dep.upgrade.blocksNodeMajor !== undefined) {
    constraintItems.push(
      renderKvItem(
        "Blocks Node major upgrade",
        yesNo(dep.upgrade.blocksNodeMajor),
      ),
    );
  }
  const constraintBlock = renderSubsection(
    "Constraints",
    '<div class="kv-grid">' + constraintItems.join("") + "</div>",
  );

  const blastRadiusBlock = renderSubsection(
    "Blast radius",
    '<div class="kv-grid">' +
      [
        renderKvItem("Used by other packages (fanIn)", dep.graph.fanIn),
        renderKvItem("Depends on packages (fanOut)", dep.graph.fanOut),
      ].join("") +
      "</div>",
  );

  const blockerLabels: Record<string, string> = {
    nodeEngine: "Node engine constraint",
    peerDependency: "Peer dependency constraints",
    nativeBindings: "Native bindings/build tooling",
    installScripts: "Install lifecycle scripts",
    deprecated: "Deprecated by author",
  };
  const blockers = dep.upgrade.blockers?.length
    ? '<div class="subsection"><div class="subsection-header"><span class="subsection-title">Upgrade blockers</span></div><ul class="bullet-list">' +
      dep.upgrade.blockers
        .map(
          (blocker) =>
            "<li>" + escapeHtml(blockerLabels[blocker] || blocker) + "</li>",
        )
        .join("") +
      "</ul></div>"
    : "";

  const upgradeSection = renderSection(
    "Upgrade & Change Impact",
    "Currency, constraints, and blast radius",
    currencyBlock +
      deprecatedBlock +
      constraintBlock +
      blastRadiusBlock +
      blockers,
  );
  const declaredSection = renderDeclaredDependencies(
    dep,
    linkableKeys,
    keysByName,
  );

  return [
    renderPackageLinks(links),
    overviewSection,
    riskSection,
    upgradeSection,
    declaredSection,
    '<details class="raw-data-toggle"><summary><span class="expand-icon" aria-hidden="true"></span>View raw data</summary>' +
      '<div class="raw-data-pane">' +
      "<pre>" +
      escapeHtml(rawJson) +
      "</pre>" +
      '<button type="button" class="copy-json-btn" aria-label="Copy raw JSON">Copy JSON</button>' +
      "</div>" +
      "</details>",
  ].join("");
}

// Main application
async function init(): Promise<void> {
  const report = await loadReportData();
  if (typeof window.__DEPENDENCY_DATA__ === "undefined") {
    window.__DEPENDENCY_DATA__ = report;
  }
  const container = document.getElementById("dependency-list")!;
  const summaryEl = document.getElementById("results-summary")!;
  const ctaUrl = buildCtaUrl(report.dependencyRadarVersion);

  // Update header info with new chip-based layout
  const projectPathEl = document.getElementById("project-path");
  if (projectPathEl) projectPathEl.textContent = report.project.projectDir;

  const ctaPrimaryLink = document.getElementById(
    "cta-primary-link",
  ) as HTMLAnchorElement | null;
  const ctaSecondaryLink = document.getElementById(
    "cta-secondary-link",
  ) as HTMLAnchorElement | null;
  if (ctaPrimaryLink) ctaPrimaryLink.href = ctaUrl;
  if (ctaSecondaryLink) ctaSecondaryLink.href = ctaUrl;

  // Git branch chip
  const gitBranchItem = document.getElementById("git-branch-item");
  const gitBranchEl = document.getElementById("git-branch");
  if (report.git?.branch && report.git.branch && gitBranchItem && gitBranchEl) {
    gitBranchEl.textContent = report.git.branch;
    gitBranchItem.style.display = "";
  }

  // Node version chip
  const nodeItem = document.getElementById("node-item");
  const nodeVersionEl = document.getElementById("node-version");
  const nodeDisclaimer = document.getElementById("node-disclaimer");
  if (report.environment && nodeItem && nodeVersionEl) {
    const runtimeVersion =
      report.environment.runtimeVersion?.replace(/^v/, "") || "unknown";
    const minRequiredMajor = report.environment.minRequiredMajor;
    nodeVersionEl.textContent =
      runtimeVersion +
      (minRequiredMajor && minRequiredMajor > 0
        ? ` (requires ≥${minRequiredMajor})`
        : "");
    nodeItem.style.display = "";
    if (minRequiredMajor && minRequiredMajor > 0 && nodeDisclaimer) {
      nodeDisclaimer.textContent =
        "Node requirement derived from dependency engine ranges.";
      nodeDisclaimer.style.display = "";
    }
  }

  // Format timestamp
  const dateEl = document.getElementById("formatted-date");
  if (dateEl && report.generatedAt) {
    try {
      const date = new Date(report.generatedAt);
      const formatted = new Intl.DateTimeFormat(undefined, {
        day: "numeric",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }).format(date);
      dateEl.textContent = formatted;
    } catch {
      dateEl.textContent = report.generatedAt;
    }
  }

  // Controls
  const controls = {
    search: document.getElementById("search") as HTMLInputElement,
    direct: document.getElementById("direct-filter") as HTMLSelectElement,
    runtime: document.getElementById("runtime-filter") as HTMLSelectElement,
    sort: document.getElementById("sort-by") as HTMLSelectElement,
    sortDirection: document.getElementById(
      "sort-direction",
    ) as HTMLButtonElement,
    hasVulns: document.getElementById("has-vulns") as HTMLInputElement,
    themeSwitch: document.getElementById("theme-switch") as HTMLElement,
    licenseToggle: document.getElementById(
      "license-toggle",
    ) as HTMLButtonElement,
    licensePanel: document.getElementById("license-panel") as HTMLElement,
    licensePermissive: document.getElementById(
      "license-permissive",
    ) as HTMLInputElement,
    licenseWeakCopyleft: document.getElementById(
      "license-weak-copyleft",
    ) as HTMLInputElement,
    licenseStrongCopyleft: document.getElementById(
      "license-strong-copyleft",
    ) as HTMLInputElement,
    licenseUnknown: document.getElementById(
      "license-unknown",
    ) as HTMLInputElement,
    licenseAll: document.getElementById("license-all") as HTMLButtonElement,
    licenseFriendly: document.getElementById(
      "license-friendly",
    ) as HTMLButtonElement,
    // New controls for redesigned filter bar
    filtersToggle: document.getElementById(
      "filters-toggle",
    ) as HTMLButtonElement,
    filterControls: document.getElementById("filter-controls") as HTMLElement,
    columnHeadersContainer: document.getElementById(
      "column-headers-container",
    ) as HTMLElement,
    packageHeader: document.getElementById(
      "package-header",
    ) as HTMLButtonElement,
    viewGraphButton: document.getElementById(
      "view-graph-btn",
    ) as HTMLButtonElement | null,
    graphBackButton: document.getElementById(
      "graph-back-btn",
    ) as HTMLButtonElement | null,
    listViewPanel: document.getElementById("list-view") as HTMLElement | null,
    graphViewPanel: document.getElementById("graph-view") as HTMLElement | null,
    graphWorkspaceSelect: document.getElementById(
      "graph-workspace",
    ) as HTMLSelectElement | null,
    graphWorkspaceWrap: document.getElementById(
      "graph-workspace-wrap",
    ) as HTMLElement | null,
    graphControls: document.getElementById(
      "graph-controls",
    ) as HTMLElement | null,
    graphCanvas: document.getElementById(
      "graph-canvas",
    ) as HTMLCanvasElement | null,
    graphCanvasShell: document.getElementById(
      "graph-canvas-shell",
    ) as HTMLElement | null,
    graphPopover: document.getElementById(
      "graph-popover",
    ) as HTMLElement | null,
    graphPopoverName: document.getElementById(
      "graph-popover-name",
    ) as HTMLElement | null,
    graphPopoverVersion: document.getElementById(
      "graph-popover-version",
    ) as HTMLElement | null,
    graphPopoverLicense: document.getElementById(
      "graph-popover-license",
    ) as HTMLElement | null,
    graphPopoverVulns: document.getElementById(
      "graph-popover-vulns",
    ) as HTMLElement | null,
    graphPopoverAmplification: document.getElementById(
      "graph-popover-amplification",
    ) as HTMLElement | null,
    graphOpenList: document.getElementById(
      "graph-open-list",
    ) as HTMLButtonElement | null,
    reportFooter: document.querySelector(
      ".report-footer",
    ) as HTMLElement | null,
  };

  // Sorting state - "name" is the default (Package name ascending)
  let sortColumn = "name";
  let sortAscending = true;
  let graphView: GraphViewHandle | null = null;
  let graphInitialized = false;

  // Theme handling
  document.documentElement.setAttribute("data-theme", "dark");
  const savedTheme = localStorage.getItem("dependency-radar-theme");
  if (savedTheme === "light") {
    document.documentElement.classList.add("light");
    controls.themeSwitch.classList.add("light");
    document.documentElement.setAttribute("data-theme", "light");
  } else {
    document.documentElement.classList.remove("light");
    controls.themeSwitch.classList.remove("light");
    document.documentElement.setAttribute("data-theme", "dark");
  }

  controls.themeSwitch.addEventListener("click", () => {
    document.documentElement.classList.toggle("light");
    controls.themeSwitch.classList.toggle("light");
    const isLight = document.documentElement.classList.contains("light");
    document.documentElement.setAttribute(
      "data-theme",
      isLight ? "light" : "dark",
    );
    localStorage.setItem("dependency-radar-theme", isLight ? "light" : "dark");
    graphView?.requestRender();
  });

  const mobileFilterQuery = window.matchMedia("(max-width: 768px)");
  let lastViewportWasMobile = mobileFilterQuery.matches;
  const setFiltersOpen = (isOpen: boolean): void => {
    if (!controls.filterControls || !controls.filtersToggle) return;
    controls.filterControls.classList.toggle("open", isOpen);
    controls.filtersToggle.classList.toggle("open", isOpen);
    controls.filtersToggle.setAttribute("aria-expanded", String(isOpen));
  };

  const syncResponsiveFilterState = (): void => {
    const isMobile = mobileFilterQuery.matches;
    if (isMobile) {
      // Mobile defaults to collapsed controls and always-open license section.
      setFiltersOpen(false);
      controls.licensePanel.classList.add("open");
      controls.licenseToggle.classList.add("open");
      lastViewportWasMobile = true;
      return;
    }
    if (lastViewportWasMobile) {
      // Reset classes when moving back to desktop from mobile.
      setFiltersOpen(false);
      controls.licensePanel.classList.remove("open");
      controls.licenseToggle.classList.remove("open");
    }
    lastViewportWasMobile = false;
  };

  // License panel toggle
  controls.licenseToggle.addEventListener("click", () => {
    if (mobileFilterQuery.matches) return;
    controls.licenseToggle.classList.toggle("open");
    controls.licensePanel.classList.toggle("open");
  });

  // Mobile filters toggle
  if (controls.filtersToggle && controls.filterControls) {
    controls.filtersToggle.addEventListener("click", () => {
      const isOpen = !controls.filterControls.classList.contains("open");
      setFiltersOpen(isOpen);
    });
  }

  window.addEventListener("resize", syncResponsiveFilterState);
  syncResponsiveFilterState();

  // Sort direction toggle (for mobile dropdown)
  controls.sortDirection.addEventListener("click", () => {
    sortAscending = !sortAscending;
    controls.sortDirection.textContent = sortAscending ? "↑" : "↓";
    updateColumnHeaders();
    renderList();
  });

  // Mobile sort dropdown change - sync with column-based sorting
  controls.sort.addEventListener("change", () => {
    sortColumn = controls.sort.value;
    updateColumnHeaders();
    renderList();
  });

  // Function to update column headers display
  function updateColumnHeaders(): void {
    if (controls.columnHeadersContainer) {
      controls.columnHeadersContainer.innerHTML = renderColumnHeaders(
        sortColumn,
        sortAscending,
      );
    }
    // Update package header sort indicator
    if (controls.packageHeader) {
      const indicator = controls.packageHeader.querySelector(".sort-indicator");
      if (indicator) {
        if (sortColumn === "name") {
          indicator.textContent = sortAscending ? " ▲" : " ▼";
          controls.packageHeader.classList.add("sorted");
        } else {
          indicator.textContent = "";
          controls.packageHeader.classList.remove("sorted");
        }
      }
    }
  }

  // Handle column header clicks for sorting
  function handleColumnHeaderClick(event: Event): void {
    const target = event.target as HTMLElement;
    const button = target.closest(".column-header") as HTMLButtonElement | null;
    if (!button) return;

    const clickedSortKey = button.dataset.sort;
    if (!clickedSortKey) return;

    if (sortColumn === clickedSortKey) {
      // Same column - toggle direction
      sortAscending = !sortAscending;
    } else {
      // Different column - set new column, ascending by default
      sortColumn = clickedSortKey;
      sortAscending = true;
    }

    // Sync mobile dropdown
    if (controls.sort) {
      controls.sort.value = sortColumn;
      controls.sortDirection.textContent = sortAscending ? "↑" : "↓";
    }

    updateColumnHeaders();
    renderList();
  }

  // Attach column header click listener (delegated)
  if (controls.columnHeadersContainer) {
    controls.columnHeadersContainer.addEventListener(
      "click",
      handleColumnHeaderClick,
    );
  }

  // Attach package header click listener
  if (controls.packageHeader) {
    controls.packageHeader.addEventListener("click", handleColumnHeaderClick);
  }

  // Initialize column headers (including package header indicator)
  updateColumnHeaders();

  // License quick actions
  controls.licenseAll.addEventListener("click", () => {
    controls.licensePermissive.checked = true;
    controls.licenseWeakCopyleft.checked = true;
    controls.licenseStrongCopyleft.checked = true;
    controls.licenseUnknown.checked = true;
    forcedVisibleDepKeys.clear();
    renderList();
  });

  controls.licenseFriendly.addEventListener("click", () => {
    controls.licensePermissive.checked = true;
    controls.licenseWeakCopyleft.checked = false;
    controls.licenseStrongCopyleft.checked = false;
    controls.licenseUnknown.checked = false;
    forcedVisibleDepKeys.clear();
    renderList();
  });

  const allDependencies = Object.values(report.dependencies || {});
  const depByKey = new Map<string, DependencyRecord>();
  allDependencies.forEach((dep) => {
    depByKey.set(getDepKey(dep.package.name, dep.package.version), dep);
  });
  const knownDepKeys = new Set(depByKey.keys());
  const depKeysByName = getDepKeysByNameIndex(knownDepKeys);
  const openDepKeys = new Set<string>();
  const forcedVisibleDepKeys = new Set<string>();
  const depElementsByKey = new Map<string, HTMLDetailsElement>();
  const copyAnnouncer = (() => {
    const existing = document.getElementById("copy-announcer");
    if (existing) return existing;
    const announcer = document.createElement("div");
    announcer.id = "copy-announcer";
    announcer.className = "sr-only";
    announcer.setAttribute("aria-live", "polite");
    document.body.appendChild(announcer);
    return announcer;
  })();

  function ensureDepDetailsRendered(detailsEl: HTMLDetailsElement): void {
    const depKey = detailsEl.dataset.depKey;
    if (!depKey) return;
    const detailsBody = detailsEl.querySelector<HTMLElement>(".dep-details");
    if (!detailsBody || detailsBody.dataset.rendered === "true") return;
    const dep = depByKey.get(depKey);
    if (!dep) return;
    detailsBody.setAttribute("aria-busy", "true");
    detailsBody.innerHTML = renderLoadingPlaceholder();
    // Defer heavy render so the placeholder paints first.
    requestAnimationFrame(() => {
      detailsBody.innerHTML = renderDepDetails(
        dep,
        knownDepKeys,
        depKeysByName,
      );
      detailsBody.dataset.rendered = "true";
      detailsBody.removeAttribute("aria-busy");
    });
  }

  async function copyRawJson(button: HTMLButtonElement): Promise<void> {
    const rawDetails = button.closest(".raw-data-toggle");
    const pre = rawDetails?.querySelector("pre");
    const json = pre?.textContent ?? "";
    if (!json) return;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(json);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = json;
        textarea.setAttribute("readonly", "true");
        textarea.style.position = "absolute";
        textarea.style.left = "-9999px";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      const originalLabel =
        button.dataset.label || button.textContent || "Copy JSON";
      button.dataset.label = originalLabel;
      button.textContent = "Copied";
      button.classList.add("copied");
      copyAnnouncer.textContent = "Copied JSON to clipboard.";
      window.setTimeout(() => {
        button.textContent = originalLabel;
        button.classList.remove("copied");
      }, 1500);
    } catch {
      copyAnnouncer.textContent = "Copy failed.";
    }
  }

  function applyFilters(): DependencyRecord[] {
    const term = (controls.search.value || "").toLowerCase();
    const directFilter = controls.direct.value;
    const runtimeFilter = controls.runtime.value;
    const hasVulns = controls.hasVulns.checked;

    const showPermissive = controls.licensePermissive.checked;
    const showWeakCopyleft = controls.licenseWeakCopyleft.checked;
    const showStrongCopyleft = controls.licenseStrongCopyleft.checked;
    const showUnknown = controls.licenseUnknown.checked;

    return allDependencies.filter((dep) => {
      const depKey = getDepKey(dep.package.name, dep.package.version);
      if (forcedVisibleDepKeys.has(depKey)) return true;
      const primaryLicense = resolvePrimaryLicense(dep);
      const licenseSearch = [
        primaryLicense.value,
        dep.compliance.license.declared?.spdxId,
        dep.compliance.license.inferred?.spdxId,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (
        term &&
        !(
          dep.package.name.toLowerCase().includes(term) ||
          licenseSearch.includes(term)
        )
      )
        return false;
      if (directFilter === "direct" && !dep.usage.direct) return false;
      if (directFilter === "transitive" && dep.usage.direct) return false;
      if (runtimeFilter !== "all" && dep.usage.scope !== runtimeFilter)
        return false;
      if (
        hasVulns &&
        severityOrder[highestSeverity(normalizeSecurity(dep).summary)] === 0
      )
        return false;

      const licenseCategory = getLicenseCategory(primaryLicense.value);
      if (licenseCategory === "permissive" && !showPermissive) return false;
      if (licenseCategory === "weakCopyleft" && !showWeakCopyleft) return false;
      if (licenseCategory === "strongCopyleft" && !showStrongCopyleft)
        return false;
      if (licenseCategory === "unknown" && !showUnknown) return false;

      return true;
    });
  }

  function sortDeps(deps: DependencyRecord[]): DependencyRecord[] {
    const sorted = [...deps];

    // Special cases: name and depth are not in COLUMN_CONFIG
    if (sortColumn === "name") {
      sorted.sort((a, b) => a.package.name.localeCompare(b.package.name));
    } else if (sortColumn === "depth") {
      sorted.sort((a, b) => a.usage.depth - b.usage.depth);
    } else {
      // Look up sort function from COLUMN_CONFIG
      const columnConfig = COLUMN_CONFIG.find(
        (col) => col.sortKey === sortColumn || col.id === sortColumn,
      );
      if (columnConfig?.sortFn) {
        sorted.sort(columnConfig.sortFn);
      } else if (columnConfig) {
        // Fallback: sort by string value
        sorted.sort((a, b) =>
          columnConfig.getValue(a).localeCompare(columnConfig.getValue(b)),
        );
      }
    }

    if (!sortAscending) sorted.reverse();
    return sorted;
  }

  function renderList(): void {
    const filtered = applyFilters();
    const deps = sortDeps(filtered);

    const totalCount =
      report.summary?.dependencyCount || allDependencies.length;
    summaryEl.innerHTML =
      "Showing <strong>" +
      deps.length +
      "</strong> of <strong>" +
      totalCount +
      "</strong> dependencies";

    if (deps.length === 0) {
      container.innerHTML =
        '<div class="empty-state"><div class="empty-state-icon">📦</div><div class="empty-state-text">No dependencies match your filters</div></div>';
      return;
    }

    container.innerHTML = deps.map(renderDep).join("");
    depElementsByKey.clear();
    container
      .querySelectorAll<HTMLDetailsElement>("details.dep-card")
      .forEach((detailsEl) => {
        const depKey = detailsEl.dataset.depKey;
        if (depKey) depElementsByKey.set(depKey, detailsEl);
      });
    openDepKeys.forEach((depKey) => {
      const detailsEl = depElementsByKey.get(depKey);
      if (!detailsEl) return;
      if (!detailsEl.open) detailsEl.open = true;
      ensureDepDetailsRendered(detailsEl);
    });
  }

  function resolveDepKeyByName(name: string): string | null {
    const candidates = depKeysByName.get(name) || [];
    if (candidates.length === 1) return candidates[0];
    return null;
  }

  function resolveDepKey(depKey: string): string | null {
    if (depByKey.has(depKey)) return depKey;
    const parsed = parseDepKey(depKey);
    if (!parsed) return resolveDepKeyByName(depKey);

    if (parsed.version.startsWith("npm:")) {
      const aliasedTarget = parsed.version.slice("npm:".length);
      const npmAliasKey =
        parsed.name +
        (aliasedTarget.startsWith("@") ? aliasedTarget : "@" + aliasedTarget);
      if (depByKey.has(npmAliasKey)) return npmAliasKey;
    }

    return resolveDepKeyByName(parsed.name);
  }

  function hasGraphDomNodes(): boolean {
    return Boolean(
      controls.graphWorkspaceSelect &&
      controls.graphWorkspaceWrap &&
      controls.graphControls &&
      controls.graphCanvas &&
      controls.graphCanvasShell &&
      controls.graphPopover &&
      controls.graphPopoverName &&
      controls.graphPopoverVersion &&
      controls.graphPopoverLicense &&
      controls.graphPopoverVulns &&
      controls.graphPopoverAmplification &&
      controls.graphOpenList,
    );
  }

  function setActiveView(view: "list" | "graph"): void {
    if (!controls.listViewPanel || !controls.graphViewPanel) {
      console.warn(
        "Dependency Radar: view panels are missing from the report DOM.",
      );
      return;
    }
    const isList = view === "list";
    if (!isList && !hasGraphDomNodes()) {
      console.warn(
        "Dependency Radar: graph view DOM nodes are missing; graph view disabled.",
      );
      return;
    }
    controls.listViewPanel.classList.toggle("active", isList);
    controls.graphViewPanel.classList.toggle("active", !isList);
    controls.listViewPanel.setAttribute("aria-hidden", String(!isList));
    controls.graphViewPanel.setAttribute("aria-hidden", String(isList));
    if (controls.viewGraphButton) {
      controls.viewGraphButton.style.display = isList ? "" : "none";
    }
    if (controls.graphBackButton) {
      controls.graphBackButton.style.display = isList ? "none" : "";
    }
    controls.reportFooter?.classList.toggle("hidden", !isList);
    document.body.classList.toggle("graph-mode", !isList);
    if (isList) {
      graphView?.setActive(false);
      return;
    }
    if (!graphInitialized) {
      graphView = initGraphView({
        report,
        knownDepKeys,
        resolveDepKey,
        workspaceSelect: controls.graphWorkspaceSelect as HTMLSelectElement,
        workspaceWrap: controls.graphWorkspaceWrap as HTMLElement,
        controlsRoot: controls.graphControls as HTMLElement,
        canvas: controls.graphCanvas as HTMLCanvasElement,
        canvasHost: controls.graphCanvasShell as HTMLElement,
        popover: controls.graphPopover as HTMLElement,
        popoverName: controls.graphPopoverName as HTMLElement,
        popoverVersion: controls.graphPopoverVersion as HTMLElement,
        popoverLicense: controls.graphPopoverLicense as HTMLElement,
        popoverVulns: controls.graphPopoverVulns as HTMLElement,
        popoverAmplification: controls.graphPopoverAmplification as HTMLElement,
        popoverOpenButton: controls.graphOpenList as HTMLButtonElement,
        onOpenList: (slug: string) => {
          openListFromGraph(slug);
        },
      });
      graphView.initGraphView();
      graphInitialized = true;
    }
    graphView?.setActive(true);
    graphView?.requestRender();
  }

  function getStickyFilterBarOffset(): number {
    const filterBar = document.querySelector<HTMLElement>(".filter-bar");
    if (!filterBar || document.body.classList.contains("graph-mode")) {
      return 0;
    }
    const stickyGap = 8;
    return Math.ceil(filterBar.getBoundingClientRect().height + stickyGap);
  }

  function scrollDependencyIntoView(
    target: HTMLElement,
    focusSummary = false,
  ): void {
    const scrollToTarget = (): void => {
      const top =
        window.scrollY +
        target.getBoundingClientRect().top -
        getStickyFilterBarOffset();
      window.scrollTo({
        top: Math.max(0, top),
        behavior: "smooth",
      });
      if (focusSummary) {
        const summary = target.querySelector<HTMLElement>("summary");
        if (summary) summary.focus({ preventScroll: true });
      }
    };

    requestAnimationFrame(() => {
      scrollToTarget();
      window.setTimeout(scrollToTarget, 60);
    });
  }

  function openListFromGraph(slug: string): void {
    setActiveView("list");
    let target = document.getElementById(getDepDomId(slug));
    if (!target && depByKey.has(slug)) {
      forcedVisibleDepKeys.add(slug);
      renderList();
      target = document.getElementById(getDepDomId(slug));
    }
    if (!target) return;

    if (target instanceof HTMLDetailsElement) {
      const depKey = target.dataset.depKey;
      if (depKey) openDepKeys.add(depKey);
      if (!target.open) target.open = true;
      ensureDepDetailsRendered(target);
    }
    target.classList.add("dep-list-highlight");
    scrollDependencyIntoView(target, true);
    window.setTimeout(() => {
      target?.classList.remove("dep-list-highlight");
    }, 2000);
  }

  // Event listeners
  const filterControls = [
    controls.search,
    controls.direct,
    controls.runtime,
    controls.sort,
    controls.hasVulns,
    controls.licensePermissive,
    controls.licenseWeakCopyleft,
    controls.licenseStrongCopyleft,
    controls.licenseUnknown,
  ];
  const handleFilterControlChange = (): void => {
    // User-driven filtering should return to normal behavior.
    forcedVisibleDepKeys.clear();
    renderList();
  };

  filterControls.forEach((ctrl) => {
    if (!ctrl) return;
    ctrl.addEventListener("input", handleFilterControlChange);
    ctrl.addEventListener("change", handleFilterControlChange);
  });

  controls.viewGraphButton?.addEventListener("click", () => {
    setActiveView("graph");
  });

  controls.graphBackButton?.addEventListener("click", () => {
    setActiveView("list");
  });

  function activateRootPackageLink(target: HTMLElement): void {
    const rawDepKey = target.getAttribute("data-dep-key");
    if (!rawDepKey) return;
    const depKey = resolveDepKey(rawDepKey);
    if (!depKey) return;
    let detailsEl = depElementsByKey.get(depKey);
    if (!detailsEl) {
      // Make linked targets visible even when active filters hide them.
      forcedVisibleDepKeys.add(depKey);
      renderList();
      detailsEl = depElementsByKey.get(depKey);
    }
    if (!detailsEl) return;
    openDepKeys.add(depKey);
    if (!detailsEl.open) detailsEl.open = true;
    ensureDepDetailsRendered(detailsEl);
    scrollDependencyIntoView(detailsEl, true);
  }

  container.addEventListener(
    "toggle",
    (event) => {
      const target = event.target as HTMLElement;
      if (!(target instanceof HTMLDetailsElement)) return;
      if (!target.classList.contains("dep-card")) return;
      const depKey = target.dataset.depKey;
      if (!depKey) return;
      if (target.open) {
        openDepKeys.add(depKey);
        ensureDepDetailsRendered(target);
      } else {
        openDepKeys.delete(depKey);
      }
    },
    true,
  );

  container.addEventListener("click", (event) => {
    const target = event.target as HTMLElement;
    const rootLink = target.closest(".root-package-link") as HTMLElement | null;
    if (rootLink) {
      event.preventDefault();
      activateRootPackageLink(rootLink);
      return;
    }
    const copyButton = target.closest(
      ".copy-json-btn",
    ) as HTMLButtonElement | null;
    if (copyButton) {
      event.preventDefault();
      void copyRawJson(copyButton);
    }
  });

  container.addEventListener("keydown", (event) => {
    const target = event.target as HTMLElement;
    const rootLink = target.closest(".root-package-link") as HTMLElement | null;
    if (!rootLink) return;
    if (event.key === " " || event.key === "Spacebar") {
      event.preventDefault();
      activateRootPackageLink(rootLink);
    }
  });
  // Initial render
  updateColumnHeaders();
  renderList();
  setActiveView("list");
}

// Initialize on DOM ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
