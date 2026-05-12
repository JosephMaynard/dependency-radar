/**
 * Dependency Radar Report - Client-side rendering
 * TypeScript version of the report rendering logic
 */

import "./style.css";
import { buildCtaUrl } from "../src/cta";
import { buildWorkspaceFilterOptions } from "../src/workspaceFilter";
import { initGraphView, type GraphViewHandle } from "./graphView";
import type {
  AggregatedData,
  DependencyRecord,
  ExecutionSignal,
  LicenseStatus,
  PackagingSignal,
  RegistryRiskSignal,
  Severity,
} from "./types";

type SupplyChainSignal = NonNullable<AggregatedData["supplyChain"]>["signals"][number];

/**
 * Load the aggregated dependency radar report data from the page or a local sample file.
 *
 * Attempts to read and parse JSON from the DOM element with id `radar-data` when its
 * text content is present and not equal to `"{}"`. If that element is missing or empty,
 * falls back to loading and parsing `./sample-data.json`.
 *
 * @returns The parsed `AggregatedData` from the page element when available; otherwise the parsed `AggregatedData` from `./sample-data.json`.
 */
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

const PACKAGING_SIGNAL_LABELS: Record<PackagingSignal, string> = {
  "bundled-dependencies": "Declares bundled dependencies",
  "embedded-shrinkwrap": "Contains embedded npm-shrinkwrap.json",
};

const REGISTRY_SIGNAL_LABELS: Record<RegistryRiskSignal, string> = {
  "recent-package": "Recently created package",
  "recent-version": "Recently published installed version",
  "low-release-history": "Low release history",
  "reactivated-package": "Reactivated after dormancy",
  "old-major-new-patch": "Recent patch on older major line",
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

/**
 * Escapes special HTML characters in a string for safe insertion into HTML.
 *
 * @param str - The input string to escape. If `null` or `undefined`, it is treated as an empty string.
 * @returns The input with `&`, `<`, `>`, and `"` replaced by their corresponding HTML entities, or an empty string for `null`/`undefined`.
 */
function escapeHtml(str: string | null | undefined): string {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Determines whether a metadata value is present and non-empty.
 *
 * Considers `null` and `undefined` absent; strings are present only if non-empty after trimming;
 * arrays are present only if they contain at least one item; plain objects are present only if they have at least one own enumerable key; all other values are considered present.
 *
 * @param value - The metadata value to test
 * @returns `true` if the value is present according to the rules above, `false` otherwise.
 */
function isPresentMetadataValue(value: unknown): boolean {
  if (value === null || typeof value === "undefined") return false;
  if (typeof value === "string") return value.trim().length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

/**
 * Format arbitrary metadata into an HTML-safe string suitable for embedding in metadata panels.
 *
 * Arrays are flattened and joined with ", ". Booleans are rendered as "Yes" or "No".
 * Plain objects are rendered as HTML-safe `key: value` lines separated by `<br>`.
 *
 * @param value - The metadata value to format (string, number, boolean, array, or object)
 * @returns An HTML-escaped string representation of `value`, using `, ` for array items and `<br>` between object entries
 */
function formatMetadataValue(value: unknown): string {
  if (Array.isArray(value)) {
    return value.map((item) => formatMetadataValue(item)).join(", ");
  }
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object" && value !== null) {
    return Object.entries(value as Record<string, unknown>)
      .filter(([, nestedValue]) => isPresentMetadataValue(nestedValue))
      .map(
        ([key, nestedValue]) =>
          escapeHtml(key) + ": " + formatMetadataValue(nestedValue),
      )
      .join("<br>");
  }
  return escapeHtml(String(value));
}

/**
 * Produces an HTML fragment for a metadata row with a label and formatted value.
 *
 * @param label - The visible label for the row
 * @param value - The metadata value to format and render; may be any type
 * @returns The HTML string for the labeled metadata row, or an empty string if `value` is not present
 */
function renderMetadataRow(label: string, value: unknown): string {
  if (!isPresentMetadataValue(value)) return "";
  return (
    '<div class="metadata-row"><div class="metadata-row-label">' +
    escapeHtml(label) +
    '</div><div class="metadata-row-value">' +
    formatMetadataValue(value) +
    "</div></div>"
  );
}

/**
 * Renders an HTML metadata section containing a title and a grid of rows when any rows are present.
 *
 * @param title - The visible section title (HTML-escaped before insertion)
 * @param rows - An array of HTML string rows; falsy entries are ignored
 * @returns The section's HTML string, or an empty string if no rows remain after filtering
 */
function renderMetadataSection(title: string, rows: string[]): string {
  const visibleRows = rows.filter(Boolean);
  if (visibleRows.length === 0) return "";
  return (
    '<section class="metadata-section"><div class="metadata-section-title">' +
    escapeHtml(title) +
    '</div><div class="metadata-grid">' +
    visibleRows.join("") +
    "</div></section>"
  );
}

/**
 * Render the "Workspaces" metadata section as an HTML string.
 *
 * Produces a section that indicates whether workspaces are enabled and the workspace type. When workspaces are enabled, the section also includes package count and, if present, a list of workspace packages showing each package's name, relative path, and runtime/dev direct-external flags.
 *
 * @param report - Aggregated report object containing a `workspaces` field used to build the section
 * @returns HTML string for the "Workspaces" metadata section
 */
function renderWorkspaceMetadata(report: AggregatedData): string {
  const workspaces = report.workspaces;
  if (!workspaces || !workspaces.enabled) {
    return renderMetadataSection("Workspaces", [
      renderMetadataRow("Enabled", false),
      renderMetadataRow("Type", workspaces?.type),
    ]);
  }
  const workspacePackages = workspaces.workspacePackages || [];
  const packageList = workspacePackages.length
    ? '<div class="metadata-list">' +
      workspacePackages
        .map(
          (workspace) =>
            '<div class="metadata-list-item"><div class="metadata-row-value">' +
            escapeHtml(workspace.name) +
            '</div><div class="metadata-muted">' +
            escapeHtml(workspace.relativePath) +
            " · runtime " +
            escapeHtml(String(workspace.directExternal.runtime)) +
            " · dev " +
            escapeHtml(String(workspace.directExternal.dev)) +
            "</div></div>",
        )
        .join("") +
      "</div>"
    : "";
  return renderMetadataSection("Workspaces", [
    renderMetadataRow("Enabled", workspaces.enabled),
    renderMetadataRow("Type", workspaces.type),
    renderMetadataRow("Package count", workspaces.packageCount),
    packageList
      ? '<div class="metadata-row"><div class="metadata-row-label">Packages</div><div>' +
        packageList +
        "</div></div>"
      : "",
  ]);
}

/**
 * Renders the "Supply Chain" metadata section from an aggregated report.
 *
 * @param report - The aggregated dependency report to extract supply chain information from
 * @returns The HTML string for the Supply Chain metadata section, or an empty string if no supply chain data is present
 */
function renderSupplyChainMetadata(report: AggregatedData): string {
  const supplyChain = report.supplyChain;
  if (!supplyChain) return "";
  const audit = supplyChain.signatureAudit;
  return renderMetadataSection("Supply Chain", [
    renderMetadataRow("Signals", supplyChain.signals?.length),
    audit
      ? renderMetadataRow("Signature audit", {
          attempted: audit.attempted,
          ok: audit.ok,
          status: audit.status,
          error: audit.error,
        })
      : "",
  ]);
}

/**
 * Renders the report metadata panel as an HTML string composed of multiple metadata sections.
 *
 * @param report - Aggregated report data containing project, environment, git, summary, workspace, and supply-chain information
 * @param formattedGeneratedAt - Preformatted generation timestamp to prefer over the raw `report.generatedAt` value
 * @returns HTML string containing the assembled metadata sections; sections with no visible rows are omitted
 */
function renderReportMetadata(report: AggregatedData, formattedGeneratedAt: string): string {
  const env = report.environment || {};
  const minRequiredMajor = env.minRequiredMajor;
  const nodeRequirementNote =
    minRequiredMajor && minRequiredMajor > 0
      ? "Node requirement derived from dependency engine ranges."
      : "";
  return [
    renderMetadataSection("Report", [
      renderMetadataRow("Dependency Radar", report.dependencyRadarVersion),
      renderMetadataRow("Schema", report.schemaVersion),
      renderMetadataRow("Generated", formattedGeneratedAt || report.generatedAt),
      renderMetadataRow("Generated raw", report.generatedAt),
    ]),
    renderMetadataSection("Project", [
      renderMetadataRow("Name", report.project.name),
      renderMetadataRow("Version", report.project.version),
      renderMetadataRow("Path", report.project.projectDir),
      renderMetadataRow("Description", report.project.description),
      renderMetadataRow("License", report.project.license),
      renderMetadataRow("Homepage", report.project.homepage),
      renderMetadataRow("Repository", report.project.repository),
      renderMetadataRow("Constraints", report.project.constraints),
      renderMetadataRow("Dependency policy", report.project.dependencyPolicySummary),
    ]),
    renderMetadataSection("Git", [
      renderMetadataRow("Branch", report.git?.branch),
    ]),
    renderMetadataSection("Environment", [
      renderMetadataRow("Node", env.nodeVersion),
      renderMetadataRow("Runtime", env.runtimeVersion),
      renderMetadataRow("Minimum required Node major", env.minRequiredMajor),
      renderMetadataRow("Target Node major", env.targetNodeMajor),
      renderMetadataRow("Platform", env.platform),
      renderMetadataRow("Architecture", env.arch),
      renderMetadataRow("CI", env.ci),
      renderMetadataRow("packageManager field", env.packageManagerField),
      renderMetadataRow("Package manager", env.packageManager),
      renderMetadataRow("Package manager version", env.packageManagerVersion),
      renderMetadataRow("Tool versions", env.toolVersions),
      renderMetadataRow("Node note", nodeRequirementNote),
    ]),
    renderWorkspaceMetadata(report),
    renderMetadataSection("Summary", [
      renderMetadataRow("Dependencies", report.summary?.dependencyCount),
      renderMetadataRow("Direct", report.summary?.directCount),
      renderMetadataRow("Transitive", report.summary?.transitiveCount),
      renderMetadataRow("Findings", report.summary?.findingCount),
    ]),
    renderSupplyChainMetadata(report),
  ]
    .filter(Boolean)
    .join("");
}

/**
 * Determine the combined risk from a vulnerability summary and a license-derived risk.
 *
 * @param summary - Security summary object whose `risk` field represents the vulnerability-derived risk (`"green" | "amber" | "red"`).
 * @param licenseRisk - License-derived risk value (`"green" | "amber" | "red"`).
 * @returns `red` if either input is `red`, `amber` if no `red` and either input is `amber`, `green` otherwise.
 */
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

/**
 * Resolve a dependency identifier into a linkable dependency key that exists in the provided set.
 *
 * Attempts to match the exact `depKey`, handles `npm:` version aliases when present, and falls back
 * to a name-based resolution using `keysByName` when `depKey` is not directly linkable.
 *
 * @param depKey - The dependency identifier to resolve (may be a full `name@version`, a plain name, or include an `npm:` alias).
 * @param linkableKeys - A set of dependency keys that are considered linkable targets.
 * @param keysByName - Optional index mapping package names to candidate depKeys for name-based resolution.
 * @returns The matching depKey from `linkableKeys` when found, or `null` if no resolvable target exists.
 */
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

/**
 * Resolve a dependency identifier into a linkable dependency key using only exact matches.
 *
 * Unlike `resolveDepLinkTarget`, this function does NOT fall back to name-only matching.
 * It only returns a match if the depKey exists exactly in `linkableKeys` or if it's an npm alias
 * that resolves to an exact key in `linkableKeys`.
 *
 * @param depKey - The dependency identifier to resolve (may be a full `name@version`, a plain name, or include an `npm:` alias).
 * @param linkableKeys - A set of dependency keys that are considered linkable targets.
 * @returns The matching depKey from `linkableKeys` when found, or `null` if no exact match exists.
 */
function resolveExactDepLinkTarget(
  depKey: string,
  linkableKeys: Set<string>,
): string | null {
  if (linkableKeys.has(depKey)) return depKey;
  const parsed = parseDepKey(depKey);
  if (!parsed) return null;

  if (parsed.version.startsWith("npm:")) {
    const aliasedTarget = parsed.version.slice("npm:".length);
    const npmAliasKey =
      parsed.name +
      (aliasedTarget.startsWith("@") ? aliasedTarget : "@" + aliasedTarget);
    if (linkableKeys.has(npmAliasKey)) return npmAliasKey;
  }
  return null;
}

/**
 * Build an index that associates dependency keys with their matching supply-chain signals.
 *
 * Matches each signal from `report.supplyChain.signals` to a single linkable dependency key by, in order:
 * 1. `signal.packageId`
 * 2. `signal.packageName` + `signal.packageVersion`
 * 3. fallback: matching versionless signals by `signal.packageName` alone
 *
 * @param report - The aggregated report object containing `supplyChain.signals`.
 * @param linkableKeys - Set of dependency keys that can be linked to detail cards.
 * @param keysByName - Precomputed index mapping package names to available dependency keys.
 * @returns A Map where each key is a resolved depKey and the value is an array of `SupplyChainSignal` objects matched to that depKey.
 */
function buildSupplyChainSignalIndex(
  report: AggregatedData,
  linkableKeys: Set<string>,
  keysByName: DepKeysByNameIndex,
): Map<string, SupplyChainSignal[]> {
  const index = new Map<string, SupplyChainSignal[]>();
  const add = (depKey: string, signal: SupplyChainSignal): void => {
    const signals = index.get(depKey) || [];
    signals.push(signal);
    index.set(depKey, signals);
  };

  for (const signal of report.supplyChain?.signals || []) {
    const candidates = [
      signal.packageId,
      signal.packageName && signal.packageVersion
        ? getDepKey(signal.packageName, signal.packageVersion)
        : undefined,
    ].filter(Boolean) as string[];
    let matched = false;
    for (const candidate of candidates) {
      const depKey = resolveExactDepLinkTarget(candidate, linkableKeys);
      if (!depKey) continue;
      add(depKey, signal);
      matched = true;
      break;
    }
    if (!matched && signal.packageName && !signal.packageVersion) {
      const depKey = resolveDepKeyByNameFromSet(signal.packageName, linkableKeys, keysByName);
      if (depKey) add(depKey, signal);
    }
  }

  return index;
}

/**
 * Renders a compact list of root packages as HTML tags, linking each item to its dependency card when a resolvable depKey exists.
 *
 * @param packages - Array of package identifiers, either strings (name or name@version) or objects with `name` and `version`. If `undefined` or empty, renders `"None"`.
 * @param maxShow - Maximum number of package items to render before truncating with a `+N more` tag.
 * @param linkableKeys - Set of known depKeys used to decide whether an item becomes a link.
 * @param keysByName - Optional index mapping package names to depKeys used to resolve ambiguous name-only references.
 * @returns An HTML string containing a `.package-list` with `.package-tag` elements; resolvable packages are rendered as anchor links (`.package-tag-link.root-package-link`) with `href="#dep-<key>"` and a `data-dep-key` attribute, non-resolvable packages are plain spans.
 */
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

/**
 * Render the “Install-time execution behaviour” subsection for a dependency.
 *
 * Builds a subsection showing execution risk, native build tooling presence, lifecycle hooks, heuristic script complexity, detected install-time signals, and an explanatory note about install-time behaviour signals.
 *
 * @param execution - Execution metadata from a dependency record containing risk, native flag, and scripts details
 * @returns HTML string for the subsection ready to be inserted into the dependency details panel
 */
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

  const packageSignals = (execution.signals || []).filter(
    (signal) => !(execution.scripts?.signals || []).includes(signal),
  );
  if (packageSignals.length) {
    const labels = packageSignals.map(
      (signal) => `${EXECUTION_SIGNAL_LABELS[signal]} (${signal})`,
    );
    items.push(
      renderKvItemHtml("Local execution signals", renderPackageList(labels, 6)),
    );
  }

  const note =
    '<div class="section-note">Execution behaviour signals are local static review cues from lifecycle scripts, entry files, package bins, or a small bounded set of package files. They do not imply compromise.</div>';

  return renderSubsection(
    "Install-time execution behaviour",
    note + '<div class="kv-grid">' + items.join("") + "</div>",
  );
}

function renderPackagingSection(
  packaging: NonNullable<DependencyRecord["packaging"]> | undefined,
): string {
  if (!packaging?.signals?.length) return "";
  const labels = packaging.signals.map(
    (signal) => `${PACKAGING_SIGNAL_LABELS[signal]} (${signal})`,
  );
  const items = [
    renderKvItemHtml("Packaging signals", renderPackageList(labels, 6)),
  ];
  if (packaging.bundledDependencies?.length) {
    items.push(
      renderKvItemHtml(
        "Bundled dependencies",
        renderPackageList(packaging.bundledDependencies, 8),
      ),
    );
  }
  return renderSubsection(
    "Package contents",
    '<div class="section-note">Packaging signals describe local package structure that may warrant review; they are not malware verdicts.</div>' +
      '<div class="kv-grid">' +
      items.join("") +
      "</div>",
  );
}

function renderRegistryEnrichmentSection(
  registry: NonNullable<DependencyRecord["supplyChain"]>["registry"] | undefined,
): string {
  if (!registry?.attempted) return "";
  const items = [
    renderKvItem("Lookup", registry.ok ? "Available" : "Unavailable"),
    renderKvItemHtml("Candidate reasons", renderPackageList(registry.candidateReasons || [], 6)),
  ];
  if (registry.error) items.push(renderKvItem("Error", registry.error));
  if (registry.signals?.length) {
    const labels = registry.signals.map(
      (signal) => `${REGISTRY_SIGNAL_LABELS[signal]} (${signal})`,
    );
    items.push(renderKvItemHtml("Registry signals", renderPackageList(labels, 6)));
  }
  if (registry.installedVersionPublishedAt) {
    items.push(renderKvItem("Installed version published", registry.installedVersionPublishedAt));
  }
  if (registry.packageCreatedAt) {
    items.push(renderKvItem("Package created", registry.packageCreatedAt));
  }
  if (typeof registry.versionCount === "number") {
    items.push(renderKvItem("Published versions", registry.versionCount));
  }
  if (registry.latestVersion) {
    items.push(renderKvItem("Latest dist-tag", registry.latestVersion));
  }
  return renderSubsection(
    "Registry metadata",
    '<div class="section-note">Targeted npm registry metadata is collected only for packages that already show local review signals, and is skipped in offline scans.</div>' +
      '<div class="kv-grid">' +
      items.join("") +
      "</div>",
  );
}

/**
 * Get a human-readable label for a supply chain signal type.
 *
 * @param type - The signal type identifier (for example `"git-dependency"` or `"missing-integrity"`)
 * @returns A human-friendly label for the signal type; if the type is not recognized, returns a title-cased version of `type`
 */
function supplyChainSignalLabel(type: string): string {
  const labels: Record<string, string> = {
    "git-dependency": "Git dependency source",
    "file-dependency": "Local dependency source",
    "non-registry-tarball": "Non-registry tarball",
    "missing-integrity": "Missing lockfile integrity",
    "unexpected-registry-host": "Unexpected registry host",
  };
  return labels[type] || titleCaseValue(type);
}

/**
 * Render a "Supply chain source" subsection showing lockfile/source signals for a dependency.
 *
 * Produces an HTML subsection containing a brief note and a key/value grid of each signal's
 * label, source, and detail. If `signals` is missing or empty, returns an empty string.
 *
 * @param signals - An optional array of supply chain signals to render
 * @returns The HTML string for the subsection, or an empty string when there are no signals
 */
function renderSupplyChainSourceSection(
  signals: SupplyChainSignal[] | undefined,
): string {
  if (!signals || signals.length === 0) return "";
  const rows = signals
    .map((signal) =>
      renderKvItem(
        supplyChainSignalLabel(signal.type),
        signal.source,
        signal.detail,
      ),
    )
    .join("");
  return renderSubsection(
    "Supply chain source",
    '<div class="section-note">Shown only when lockfile source metadata is unusual or incomplete.</div>' +
      '<div class="kv-grid">' +
      rows +
      "</div>",
    "Lockfile source signals",
    "warning",
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

/**
 * Build the full HTML content for a dependency's expanded detail panel.
 *
 * Renders overview, license, vulnerability, execution, supply-chain source, upgrade/change impact, declared sub-dependencies, package links, and a raw JSON pane for the given dependency.
 *
 * @param dep - The dependency record to render detail content for.
 * @param linkableKeys - Set of dependency keys that can be linked to within the report.
 * @param keysByName - Optional index mapping package name to available dependency keys (used to resolve ambiguous links).
 * @param supplyChainSignals - Optional list of supply-chain source signals associated with this dependency; when provided a "Supply chain source" subsection will be included.
 * @returns An HTML string containing the complete detail content for the dependency card.
 */
function renderDepDetails(
  dep: DependencyRecord,
  linkableKeys: Set<string>,
  keysByName?: DepKeysByNameIndex,
  supplyChainSignals?: SupplyChainSignal[],
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
    !dep.usage.direct
      ? renderKvItemHtml(
          "Introduced via root packages",
          renderRootPackageList(
            dep.usage.origins.topRootPackages,
            8,
            linkableKeys,
            keysByName,
          ),
        )
      : "",
    !dep.usage.direct
      ? renderKvItem("Direct roots", dep.usage.origins.rootPackageCount)
      : "",
    !dep.usage.direct
      ? renderKvItemHtml(
          "Direct parents",
          renderDependencyIdList(
            dep.usage.origins.topParentPackages,
            8,
            linkableKeys,
            keysByName,
          ),
        )
      : "",
    !dep.usage.direct
      ? renderKvItem(
          "Direct parents count",
          dep.usage.origins.parentPackageCount ?? 0,
        )
      : "",
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
  const packagingBlock = renderPackagingSection(dep.packaging);
  const registryBlock = renderRegistryEnrichmentSection(dep.supplyChain?.registry);
  const supplyChainBlock = renderSupplyChainSourceSection(supplyChainSignals);

  const riskSection = renderSection(
    "Risk & Compliance",
    "License, vulnerabilities, install-time execution, and unusual source signals",
    licenseBlock + vulnBlock + executionBlock + packagingBlock + registryBlock + supplyChainBlock,
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

/**
 * Initialize the Dependency Radar UI, load report data, and wire all controls and event handlers.
 *
 * Loads and caches the report, renders header metadata and column headers, builds workspace and dependency indices,
 * configures theme, responsive filters, sorting and license controls, prepares graph/list view switching,
 * sets up lazy dependency-detail rendering and copy-to-clipboard handling, and performs the initial list render.
 */
async function init(): Promise<void> {
  const report = await loadReportData();
  if (typeof window.__DEPENDENCY_DATA__ === "undefined") {
    window.__DEPENDENCY_DATA__ = report;
  }
  const container = document.getElementById("dependency-list")!;
  const summaryEl = document.getElementById("results-summary")!;
  const ctaUrl = buildCtaUrl(report.dependencyRadarVersion);

  // Update header info with chip-based layout and detailed metadata dropdown
  const projectPathEl = document.getElementById("project-path");
  if (projectPathEl) {
    projectPathEl.textContent = report.project.name || report.project.projectDir;
    projectPathEl.title = report.project.projectDir;
  }
  const metadataToggle = document.getElementById(
    "metadata-toggle",
  ) as HTMLButtonElement | null;
  const metadataPanel = document.getElementById(
    "metadata-panel",
  ) as HTMLElement | null;

  const ctaPrimaryLink = document.getElementById(
    "cta-primary-link",
  ) as HTMLAnchorElement | null;
  if (ctaPrimaryLink) ctaPrimaryLink.href = ctaUrl;

  // Format timestamp
  const dateEl = document.getElementById("formatted-date");
  let formattedGeneratedAt = report.generatedAt || "";
  if (dateEl && report.generatedAt) {
    try {
      const date = new Date(report.generatedAt);
      if (Number.isNaN(date.getTime())) {
        formattedGeneratedAt = report.generatedAt;
        dateEl.textContent = report.generatedAt;
      } else {
        formattedGeneratedAt = new Intl.DateTimeFormat(undefined, {
          day: "numeric",
          month: "short",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        }).format(date);
        dateEl.textContent = formattedGeneratedAt;
      }
    } catch {
      formattedGeneratedAt = report.generatedAt;
      dateEl.textContent = report.generatedAt;
    }
  }
  if (metadataPanel) {
    metadataPanel.innerHTML = renderReportMetadata(report, formattedGeneratedAt);
    metadataPanel.hidden = false;
    metadataPanel.inert = true;
    metadataPanel.setAttribute("aria-hidden", "true");
  }
  const setMetadataOpen = (isOpen: boolean): void => {
    if (!metadataToggle || !metadataPanel) return;
    metadataPanel.classList.toggle("open", isOpen);
    metadataPanel.inert = !isOpen;
    metadataPanel.setAttribute("aria-hidden", String(!isOpen));
    metadataToggle.classList.toggle("open", isOpen);
    metadataToggle.setAttribute("aria-expanded", String(isOpen));
  };
  metadataToggle?.addEventListener("click", () => {
    const isOpen = !metadataPanel?.classList.contains("open");
    setMetadataOpen(isOpen);
  });
  document.addEventListener("click", (event) => {
    if (!metadataToggle || !metadataPanel) return;
    if (!metadataPanel.classList.contains("open")) return;
    const target = event.target as Node;
    if (metadataToggle.contains(target) || metadataPanel.contains(target)) return;
    setMetadataOpen(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") setMetadataOpen(false);
  });

  // Controls
  const controls = {
    search: document.getElementById("search") as HTMLInputElement,
    direct: document.getElementById("direct-filter") as HTMLSelectElement,
    runtime: document.getElementById("runtime-filter") as HTMLSelectElement,
    workspace: document.getElementById("workspace-filter") as HTMLSelectElement,
    workspaceWrap: document.getElementById("workspace-filter-wrap") as HTMLElement,
    sort: document.getElementById("sort-by") as HTMLSelectElement,
    sortDirection: document.getElementById(
      "sort-direction",
    ) as HTMLButtonElement,
    hasVulns: document.getElementById("has-vulns") as HTMLInputElement,
    themeSwitch: document.getElementById("theme-switch") as HTMLButtonElement,
    licenseToggle: document.getElementById(
      "license-toggle",
    ) as HTMLButtonElement | null,
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
    filterCountBadge: document.getElementById(
      "filter-count-badge",
    ) as HTMLElement | null,
    filterControls: document.getElementById("filter-controls") as HTMLElement,
    activeFiltersRow: document.getElementById(
      "active-filters-row",
    ) as HTMLElement | null,
    activeFilterChips: document.getElementById(
      "active-filter-chips",
    ) as HTMLElement | null,
    activeFilterClear: document.getElementById(
      "active-filter-clear",
    ) as HTMLButtonElement | null,
    clearAllFilters: document.getElementById(
      "clear-all-filters",
    ) as HTMLButtonElement | null,
    licensePermissiveLabel: document.getElementById(
      "license-permissive-label",
    ) as HTMLElement | null,
    licenseWeakCopyleftLabel: document.getElementById(
      "license-weak-copyleft-label",
    ) as HTMLElement | null,
    licenseStrongCopyleftLabel: document.getElementById(
      "license-strong-copyleft-label",
    ) as HTMLElement | null,
    licenseUnknownLabel: document.getElementById(
      "license-unknown-label",
    ) as HTMLElement | null,
    hasVulnsLabel: document.getElementById(
      "has-vulns-label",
    ) as HTMLElement | null,
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
    controls.themeSwitch.setAttribute("aria-pressed", "true");
    document.documentElement.setAttribute("data-theme", "light");
  } else {
    document.documentElement.classList.remove("light");
    controls.themeSwitch.classList.remove("light");
    controls.themeSwitch.setAttribute("aria-pressed", "false");
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
    controls.themeSwitch.setAttribute("aria-pressed", String(isLight));
    localStorage.setItem("dependency-radar-theme", isLight ? "light" : "dark");
    graphView?.requestRender();
  });

  const mobileFilterQuery = window.matchMedia("(max-width: 768px)");
  let lastViewportWasMobile = mobileFilterQuery.matches;
  const setFiltersOpen = (isOpen: boolean): void => {
    if (!controls.filterControls || !controls.filtersToggle) return;
    controls.filterControls.classList.toggle("open", isOpen);
    controls.filterControls.inert = !isOpen;
    controls.filterControls.setAttribute("aria-hidden", String(!isOpen));
    controls.filtersToggle.classList.toggle("open", isOpen);
    controls.filtersToggle.setAttribute("aria-expanded", String(isOpen));
    if (isOpen) setMetadataOpen(false);
  };

  const syncResponsiveFilterState = (): void => {
    const isMobile = mobileFilterQuery.matches;
    if (isMobile) {
      setFiltersOpen(false);
      lastViewportWasMobile = true;
      return;
    }
    if (lastViewportWasMobile) {
      setFiltersOpen(false);
    }
    lastViewportWasMobile = false;
  };

  // Filters popover toggle
  if (controls.filtersToggle && controls.filterControls) {
    controls.filtersToggle.addEventListener("click", () => {
      const isOpen = !controls.filterControls.classList.contains("open");
      setFiltersOpen(isOpen);
    });
  }
  document.addEventListener("click", (event) => {
    if (!controls.filterControls || !controls.filtersToggle) return;
    const target = event.target as Node;
    if (
      !controls.filterControls.contains(target) &&
      !controls.filtersToggle.contains(target)
    ) {
      setFiltersOpen(false);
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") setFiltersOpen(false);
  });

  setFiltersOpen(false);
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
  const getDependencyWorkspaces = (dep: DependencyRecord): string[] => {
    const workspaces = dep.usage.origins.workspaces || [];
    return workspaces.length > 0 ? workspaces : ["root"];
  };
  const workspaceNames = Array.from(
    new Set([
      ...buildWorkspaceFilterOptions(report),
      ...allDependencies.flatMap(getDependencyWorkspaces),
    ]),
  ).sort((a, b) => {
    if (a === "root") return -1;
    if (b === "root") return 1;
    return a.localeCompare(b);
  });
  const formatCount = (label: string, count: number): string =>
    label + " (" + count + ")";
  const hasVulnerabilities = (dep: DependencyRecord): boolean =>
    severityOrder[highestSeverity(normalizeSecurity(dep).summary)] > 0;
  const countBy = (
    predicate: (dep: DependencyRecord) => boolean,
  ): number => allDependencies.reduce((count, dep) => count + (predicate(dep) ? 1 : 0), 0);
  /**
   * Update visible filter option labels with current dependency counts.
   *
   * Recomputes counts from the global `allDependencies` dataset and writes them into the UI filter controls.
   * Specifically updates:
   * - the total/"All", "Direct", and "Transitive" counts;
   * - runtime scope option labels (Production/Development/Optional/Peer);
   * - license category labels (Permissive, Weak Copyleft, Strong Copyleft, Other / Unknown);
   * - the "Has vulnerabilities" count.
   *
   * This function mutates DOM elements found on the `controls` object by setting their `textContent`.
   */
  function updateFilterOptionCounts(): void {
    const total = allDependencies.length;
    controls.direct.options[0].textContent = formatCount("All", total);
    controls.direct.options[1].textContent = formatCount(
      "Direct",
      countBy((dep) => dep.usage.direct),
    );
    controls.direct.options[2].textContent = formatCount(
      "Transitive",
      countBy((dep) => !dep.usage.direct),
    );

    const scopeLabels: Record<string, string> = {
      all: "All",
      runtime: "Production",
      dev: "Development",
      optional: "Optional",
      peer: "Peer",
    };
    Array.from(controls.runtime.options).forEach((option) => {
      option.textContent = formatCount(
        scopeLabels[option.value] || option.textContent || option.value,
        option.value === "all"
          ? total
          : countBy((dep) => dep.usage.scope === option.value),
      );
    });

    const licenseCounts = {
      permissive: 0,
      weakCopyleft: 0,
      strongCopyleft: 0,
      unknown: 0,
    };
    allDependencies.forEach((dep) => {
      licenseCounts[getLicenseCategory(resolvePrimaryLicense(dep).value)] += 1;
    });
    if (controls.licensePermissiveLabel)
      controls.licensePermissiveLabel.textContent = formatCount(
        "Permissive",
        licenseCounts.permissive,
      );
    if (controls.licenseWeakCopyleftLabel)
      controls.licenseWeakCopyleftLabel.textContent = formatCount(
        "Weak Copyleft",
        licenseCounts.weakCopyleft,
      );
    if (controls.licenseStrongCopyleftLabel)
      controls.licenseStrongCopyleftLabel.textContent = formatCount(
        "Strong Copyleft",
        licenseCounts.strongCopyleft,
      );
    if (controls.licenseUnknownLabel)
      controls.licenseUnknownLabel.textContent = formatCount(
        "Other / Unknown",
        licenseCounts.unknown,
      );
    if (controls.hasVulnsLabel)
      controls.hasVulnsLabel.textContent = formatCount(
        "Has vulnerabilities",
        countBy(hasVulnerabilities),
      );
  }
  if (controls.workspace && controls.workspaceWrap && workspaceNames.length > 1) {
    controls.workspace.textContent = "";
    const allOption = document.createElement("option");
    allOption.value = "all";
    allOption.textContent = formatCount("All workspaces", allDependencies.length);
    controls.workspace.appendChild(allOption);
    workspaceNames.forEach((workspaceName) => {
      const option = document.createElement("option");
      option.value = workspaceName;
      option.textContent = formatCount(
        workspaceName === "root" ? "Workspace root" : workspaceName,
        countBy((dep) =>
          getDependencyWorkspaces(dep).includes(workspaceName),
        ),
      );
      controls.workspace.appendChild(option);
    });
    controls.workspaceWrap.classList.remove("hidden");
  }
  updateFilterOptionCounts();
  const depByKey = new Map<string, DependencyRecord>();
  allDependencies.forEach((dep) => {
    depByKey.set(getDepKey(dep.package.name, dep.package.version), dep);
  });
  const knownDepKeys = new Set(depByKey.keys());
  const depKeysByName = getDepKeysByNameIndex(knownDepKeys);
  const supplyChainSignalsByKey = buildSupplyChainSignalIndex(
    report,
    knownDepKeys,
    depKeysByName,
  );
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

  /**
   * Lazily renders and injects the full dependency detail HTML into a dependency card's details container.
   *
   * If the details are not yet rendered and the element's `data-dep-key` matches a known dependency, this:
   * - inserts a lightweight loading placeholder,
   * - marks the container as busy,
   * - replaces the placeholder with the full rendered details on the next animation frame,
   * - marks the container as rendered (`data-rendered="true"`) and clears the busy state.
   *
   * No action is taken when `data-dep-key` is missing, the dependency cannot be found, or the details are already rendered.
   *
   * @param detailsEl - The <details> element for a dependency card; must contain a child `.dep-details` element and a `data-dep-key` attribute.
   */
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
        supplyChainSignalsByKey.get(depKey),
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

  /**
   * Produce the list of dependencies that satisfy the current UI filter and search settings.
   *
   * Filters applied include search term (package name and license fields), direct vs transitive,
   * runtime scope, workspace membership, presence of vulnerabilities, and enabled license categories.
   * Dependencies present in `forcedVisibleDepKeys` bypass filtering and are always included.
   *
   * @returns An array of DependencyRecord objects that match the active filters and search term.
   */
  function applyFilters(): DependencyRecord[] {
    const term = (controls.search.value || "").toLowerCase();
    const directFilter = controls.direct.value;
    const runtimeFilter = controls.runtime.value;
    const workspaceFilter = controls.workspace?.value || "all";
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
        workspaceFilter !== "all" &&
        !getDependencyWorkspaces(dep).includes(workspaceFilter)
      )
        return false;
      if (
        hasVulns &&
        !hasVulnerabilities(dep)
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

  type ActiveFilterChip = {
    id: string;
    label: string;
    remove: () => void;
  };

  /**
   * Get the display label of a select's currently chosen option, omitting a trailing parenthesized count.
   *
   * @param select - The HTMLSelectElement to read the selected option from
   * @returns The selected option's text with a trailing ` (n)` count removed, or an empty string if no option is selected
   */
  function selectedOptionLabel(select: HTMLSelectElement): string {
    const option = select.selectedOptions[0];
    return (option?.textContent || "").replace(/\s+\(\d+\)$/, "");
  }

  /**
   * Restore all non-search filter controls to their initial (unrestricted) state.
   *
   * Sets the direct and runtime scope selectors to "all", resets the workspace selector to "all" if present,
   * clears the "has vulnerabilities" checkbox, and enables all license-category checkboxes.
   */
  function resetNonSearchFilters(): void {
    controls.direct.value = "all";
    controls.runtime.value = "all";
    if (controls.workspace) controls.workspace.value = "all";
    controls.hasVulns.checked = false;
    controls.licensePermissive.checked = true;
    controls.licenseWeakCopyleft.checked = true;
    controls.licenseStrongCopyleft.checked = true;
    controls.licenseUnknown.checked = true;
  }

  /**
   * Clear all active filters in the UI.
   *
   * Resets the search input to an empty string and restores non-search filter controls
   * (direct/runtime/workspace/hasVulns and license checkboxes) to their default enabled state.
   */
  function resetAllFilters(): void {
    controls.search.value = "";
    resetNonSearchFilters();
  }

  /**
   * Build an array of active filter chip models reflecting the current UI filter state.
   *
   * The returned chips represent non-default filters: a search term, non-"all" type/scope/workspace selections,
   * disabled license category checkboxes, and the "has vulnerabilities" toggle. Each chip includes an `id`, a
   * human-readable `label`, and a `remove` callback that restores the corresponding control to its default value.
   *
   * @returns An array of `ActiveFilterChip` objects; each chip has `id`, `label`, and a `remove` function that resets the related control to its default state.
   */
  function getActiveFilterChips(): ActiveFilterChip[] {
    const chips: ActiveFilterChip[] = [];
    const searchValue = controls.search.value.trim();
    if (searchValue) {
      chips.push({
        id: "search",
        label: "Search: " + searchValue,
        remove: () => {
          controls.search.value = "";
        },
      });
    }
    if (controls.direct.value !== "all") {
      chips.push({
        id: "type",
        label: "Type: " + selectedOptionLabel(controls.direct),
        remove: () => {
          controls.direct.value = "all";
        },
      });
    }
    if (controls.runtime.value !== "all") {
      chips.push({
        id: "scope",
        label: "Scope: " + selectedOptionLabel(controls.runtime),
        remove: () => {
          controls.runtime.value = "all";
        },
      });
    }
    if (controls.workspace && controls.workspace.value !== "all") {
      chips.push({
        id: "workspace",
        label: "Workspace: " + selectedOptionLabel(controls.workspace),
        remove: () => {
          controls.workspace.value = "all";
        },
      });
    }
    const licenseFilters = [
      {
        id: "license-permissive",
        checked: controls.licensePermissive.checked,
        label: "License: Permissive",
        reset: () => {
          controls.licensePermissive.checked = true;
        },
      },
      {
        id: "license-weak-copyleft",
        checked: controls.licenseWeakCopyleft.checked,
        label: "License: Weak Copyleft",
        reset: () => {
          controls.licenseWeakCopyleft.checked = true;
        },
      },
      {
        id: "license-strong-copyleft",
        checked: controls.licenseStrongCopyleft.checked,
        label: "License: Strong Copyleft",
        reset: () => {
          controls.licenseStrongCopyleft.checked = true;
        },
      },
      {
        id: "license-unknown",
        checked: controls.licenseUnknown.checked,
        label: "License: Other / Unknown",
        reset: () => {
          controls.licenseUnknown.checked = true;
        },
      },
    ];
    licenseFilters.forEach((filter) => {
      if (filter.checked) return;
      chips.push({
        id: filter.id,
        label: filter.label,
        remove: filter.reset,
      });
    });
    if (controls.hasVulns.checked) {
      chips.push({
        id: "has-vulns",
        label: "Has vulnerabilities",
        remove: () => {
          controls.hasVulns.checked = false;
        },
      });
    }
    return chips;
  }

  /**
   * Synchronizes the filter UI to reflect the current set of active filters.
   *
   * Updates the filters toggle state, the numeric filter-count badge, the visibility
   * of the active-filters row, and the rendered list of active filter chips.
   */
  function syncActiveFilterUi(): void {
    const chips = getActiveFilterChips();
    const activeCount = chips.length;
    controls.filtersToggle.classList.toggle("has-active-filters", activeCount > 0);
    if (controls.filterCountBadge) {
      controls.filterCountBadge.hidden = activeCount === 0;
      controls.filterCountBadge.textContent = String(activeCount);
    }
    if (controls.activeFiltersRow && controls.activeFilterChips) {
      controls.activeFiltersRow.hidden = activeCount === 0;
      controls.activeFilterChips.innerHTML = chips
        .map(
          (chip) =>
            '<span class="active-filter-chip">' +
            escapeHtml(chip.label) +
            '<button type="button" class="active-filter-remove" data-filter-chip="' +
            escapeHtml(chip.id) +
            '" aria-label="Remove ' +
            escapeHtml(chip.label) +
            '">×</button></span>',
        )
        .join("");
    }
  }

  /**
   * Sorts a list of dependency records according to the active sort column and sort direction.
   *
   * @param deps - The array of dependency records to sort.
   * @returns A new array containing `deps` sorted by the current `sortColumn` and `sortAscending` settings.
   */
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

  /**
   * Updates the visible dependency list and summary to reflect current filters and sort state.
   *
   * Applies the active filters and sorting, updates the results summary text (including optional workspace context), renders either an empty-state message or the dependency cards into the list container, rebuilds the internal mapping of dependency DOM elements, and opens and lazily renders any dependency cards that are tracked as open.
   */
  function renderList(): void {
    syncActiveFilterUi();
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
    if ((controls.workspace?.value || "all") !== "all") {
      summaryEl.innerHTML +=
        ' in <strong>' + escapeHtml(controls.workspace.value) + '</strong>';
    }

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
    controls.workspace,
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

  controls.activeFilterChips?.addEventListener("click", (event) => {
    const button = (event.target as HTMLElement).closest<HTMLButtonElement>(
      "[data-filter-chip]",
    );
    if (!button) return;
    const chip = getActiveFilterChips().find(
      (item) => item.id === button.dataset.filterChip,
    );
    if (!chip) return;
    chip.remove();
    handleFilterControlChange();
  });

  const clearFilters = (): void => {
    resetAllFilters();
    handleFilterControlChange();
  };
  controls.activeFilterClear?.addEventListener("click", clearFilters);
  controls.clearAllFilters?.addEventListener("click", clearFilters);

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
