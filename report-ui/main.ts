/**
 * Dependency Radar Report - Client-side rendering
 * TypeScript version of the report rendering logic
 */

import "./style.css";
import {
  buildReportOverallRisk,
  buildReportKeyPoints,
  reportVulnerabilityTotal,
} from "../src/reportDetailRules";
import { buildWorkspaceFilterOptions } from "../src/workspaceFilter";
import { adaptDataset, initGraphView, type GraphViewHandle } from "./graphView";
import { buildVizModel, type VizModel } from "./vizModel";
import { FINE_PRINT } from "./finePrint";
import type { GraphRoute } from "./graphModes";
import { buildDomTree, computeReachCounts } from "./domTree";
import { initGraphModes, type GraphModesHandle } from "./graphModes";
import { DEFAULT_GRAPH_FILTERS } from "./vizModel";
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
    id: "subdeps",
    label: "Sub-deps",
    sortKey: "subdeps",
    getValue: (dep) => {
      const count = getSubDepCount(`${dep.package.name}@${dep.package.version}`);
      return count === undefined ? "—" : count.toLocaleString();
    },
    getTone: () => "gray",
    sortFn: (a, b) =>
      (getSubDepCount(`${a.package.name}@${a.package.version}`) ?? -1) -
      (getSubDepCount(`${b.package.name}@${b.package.version}`) ?? -1),
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
  {
    id: "maintenance",
    label: "Maintenance",
    sortKey: "maintenance",
    getValue: (dep) => getMaintenanceStatusLabel(dep.maintenance?.status),
    getTone: (dep) => getMaintenanceStatusTone(dep.maintenance?.status),
    sortFn: (a, b) =>
      maintenanceStatusOrder(b.maintenance?.status) -
      maintenanceStatusOrder(a.maintenance?.status),
  },
];

const MAINTENANCE_STATUS_LABELS: Record<string, string> = {
  deprecated: "Deprecated",
  archived: "Archived",
  unmaintained: "Unmaintained",
  stale: "Stale",
  slowing: "Slowing",
  active: "Active",
  unknown: "—",
};

function getMaintenanceStatusLabel(status?: string): string {
  if (!status) return "—";
  return MAINTENANCE_STATUS_LABELS[status] || "—";
}

function getMaintenanceStatusTone(status?: string): string {
  if (status === "deprecated" || status === "archived") return "red";
  if (status === "unmaintained" || status === "stale" || status === "slowing")
    return "amber";
  if (status === "active") return "green";
  return "gray";
}

function maintenanceStatusOrder(status?: string): number {
  const order: Record<string, number> = {
    deprecated: 6,
    archived: 5,
    unmaintained: 4,
    stale: 3,
    slowing: 2,
    active: 1,
  };
  return status ? order[status] || 0 : 0;
}

function hasMaintenanceConcern(dep: DependencyRecord): boolean {
  const status = dep.maintenance?.status;
  return (
    status === "deprecated" ||
    status === "archived" ||
    status === "unmaintained" ||
    status === "stale" ||
    status === "slowing"
  );
}

function hasReplacementSuggestion(dep: DependencyRecord): boolean {
  return Boolean(dep.replacement?.replacements?.length);
}

function hasLicenseIssue(dep: DependencyRecord): boolean {
  return dep.compliance.licenseRisk !== "green";
}

function hasUpgradeBlocker(dep: DependencyRecord): boolean {
  return Boolean(dep.upgrade.blocksNodeMajor || dep.upgrade.blockers?.length);
}

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
    renderMetadataSection("Scan evidence", [
      renderMetadataRow("Complete", report.scanStatus?.complete),
      renderMetadataRow("Collectors", report.scanStatus?.collectors),
      renderMetadataRow("Warnings", report.scanStatus?.warnings),
    ]),
    renderSupplyChainMetadata(report),
  ]
    .filter(Boolean)
    .join("");
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

/** Inline (i) button opening the shared fine-print note for a topic. */
function finePrintBtnHtml(topic: keyof typeof FINE_PRINT): string {
  const note = FINE_PRINT[topic];
  return (
    '<button type="button" class="fine-print-btn" data-fine-topic="' +
    escapeHtml(String(topic)) +
    '" aria-haspopup="true" aria-expanded="false" aria-label="About: ' +
    escapeHtml(note?.title ?? String(topic)) +
    '">\u24d8</button>'
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

const DATE_ONLY_FORMAT: Intl.DateTimeFormatOptions = {
  day: "numeric",
  month: "short",
  year: "numeric",
};
const DATE_TIME_FORMAT: Intl.DateTimeFormatOptions = {
  ...DATE_ONLY_FORMAT,
  hour: "2-digit",
  minute: "2-digit",
};

/**
 * Format an ISO timestamp in the viewer's locale, matching the header's
 * generated-at treatment. Unparseable values fall through unchanged so a
 * malformed timestamp still shows its raw value rather than "Invalid Date".
 */
function formatTimestamp(value: string | undefined, withTime = false): string {
  if (!value) return "";
  try {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return new Intl.DateTimeFormat(
      undefined,
      withTime ? DATE_TIME_FORMAT : DATE_ONLY_FORMAT,
    ).format(date);
  } catch {
    return value;
  }
}

/**
 * Render a whole-month age as review-friendly prose. Sub-month gaps read as
 * "~0 months ago" otherwise, which looks like a missing value.
 */
function formatMonthsAgo(months: number): string {
  if (months <= 0) return "Less than a month ago";
  if (months === 1) return "About 1 month ago";
  return `About ${months} months ago`;
}

function renderRiskValue(
  value: string | number,
  risk: "green" | "amber" | "red" | "gray",
): string {
  return (
    '<span class="kv-value risk-value"><span class="risk-dot ' +
    risk +
    '"></span>' +
    escapeHtml(String(value)) +
    "</span>"
  );
}

function renderStatusChip(
  label: string,
  tone: "neutral" | "green" | "amber" | "red" | "replacement" = "neutral",
): string {
  return (
    '<span class="status-chip ' +
    tone +
    '">' +
    escapeHtml(label) +
    "</span>"
  );
}

// Audit is the only risk signal on the chip strip that needs the network.
// Captured at init so a "Vulnerability: None" chip stays neutral rather than
// claiming a green all-clear on a scan where the audit never ran.
let auditCollectorStatus = "available";
let auditCollectorAvailable = true;

/**
 * Whether the package's own files were readable during the scan.
 *
 * deriveExecutionInfo returns undefined both for a package it inspected and
 * found clean and for one it could never open, so absence of `execution` says
 * nothing on its own. fileCount is only set when the package was measured on
 * disk, which separates the two: a lockfile-only scan (no node_modules) has
 * neither, while a normal scan has fileCount on every package.
 */
function executionWasInspected(dep: DependencyRecord): boolean {
  return (
    dep.execution !== undefined || typeof dep.package.fileCount === "number"
  );
}

/**
 * Why a vulnerability figure is not authoritative. A partial audit did run and
 * covered some packages, so saying it "did not run" would be wrong.
 */
function auditCoverageNote(): string {
  return auditCollectorStatus === "partial"
    ? "audit incomplete"
    : "audit did not run";
}

function buildStatusChips(
  dep: DependencyRecord,
  summary: SecuritySummary,
  licenseText: string,
): string {
  const vulnTotal = reportVulnerabilityTotal(summary);
  const installRisk = dep.execution?.risk || "green";
  const blocker = dep.upgrade.blocksNodeMajor || !!dep.upgrade.blockers?.length;
  // Without audit data a bare "None" would assert a clean result the scan
  // never checked for. "None reported" describes what the report holds, and
  // the neutral tone keeps it from reading as a green all-clear.
  const vulnUnchecked = vulnTotal === 0 && !auditCollectorAvailable;
  const chips = [
    renderStatusChip(dep.usage.direct ? "Direct dependency" : "Transitive dependency"),
    renderStatusChip(scopeLabel(dep.usage.scope)),
    renderStatusChip(
      vulnTotal > 0
        ? "Vulnerability: " + titleCaseValue(summary.highest)
        : vulnUnchecked
          ? "Vulnerability: None reported"
          : "Vulnerability: None",
      vulnUnchecked ? "neutral" : summary.risk,
    ),
    renderStatusChip("Licence: " + licenseText, dep.compliance.licenseRisk),
    executionWasInspected(dep)
      ? renderStatusChip("Install risk: " + toneToString(installRisk), installRisk)
      : renderStatusChip("Install risk: Not inspected"),
    renderStatusChip(blocker ? "Upgrade blocker" : "No upgrade blocker", blocker ? "amber" : "neutral"),
  ];
  // Maintenance is omitted entirely when the collector never ran (offline or
  // --no-maintenance), rather than claiming an "Active" or "Unknown" status
  // the scan has no basis for.
  const maintenanceStatus = dep.maintenance?.status;
  if (maintenanceStatus && maintenanceStatus !== "unknown") {
    const tone = getMaintenanceStatusTone(maintenanceStatus);
    chips.push(
      renderStatusChip(
        "Maintenance: " + getMaintenanceStatusLabel(maintenanceStatus),
        tone === "green" || tone === "amber" || tone === "red"
          ? tone
          : "neutral",
      ),
    );
  } else if (dep.maintenance?.attempted) {
    chips.push(renderStatusChip("Maintenance: Unknown"));
  }
  // A suggestion is an opportunity rather than a risk, so it gets its own tone
  // and is dropped when absent instead of showing a "none" chip on every row.
  if (dep.replacement?.replacements?.length) {
    chips.push(renderStatusChip("Replacement available (e18e)", "replacement"));
  }
  return '<div class="status-chip-strip">' + chips.join("") + "</div>";
}

function renderKeyPoints(points: string[]): string {
  return [
    '<div class="key-points">',
    '<div class="section-header compact"><span class="section-title">Key points</span></div>',
    '<ul class="key-points-list">',
    points.map((point) => '<li>' + escapeHtml(point) + "</li>").join(""),
    "</ul>",
    "</div>",
  ].join("");
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

/**
 * Map a risk tone onto the subsection tint class, so a section with an issue
 * is coloured the same way the Maintenance section already is. Green and
 * missing risks stay untinted.
 */
function subsectionTone(
  risk: "red" | "amber" | "green" | undefined,
): string | undefined {
  if (risk === "red") return "warning";
  if (risk === "amber") return "caution";
  return undefined;
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
    undefined,
    subsectionTone(execution.risk),
  );
}

/**
 * Render the "Package contents" subsection HTML for a dependency when packaging signals exist.
 *
 * @param packaging - Packaging metadata from the dependency; expected to contain a `signals` array and optional `bundledDependencies` array. If `packaging` is undefined or has no `signals`, nothing is rendered.
 * @returns An HTML string containing the "Package contents" subsection (including packaging signal labels and bundled dependencies when present), or an empty string if there are no packaging signals.
 */
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

/**
 * Render an HTML subsection showing registry enrichment metadata for a dependency.
 *
 * @param registry - Registry enrichment data from the dependency's `supplyChain` object; may be `undefined` or have `attempted: false`.
 * @returns The HTML string for the "Registry metadata" subsection, or an empty string when no registry lookup was attempted.
 */
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
    items.push(
      renderKvItem(
        "Installed version published",
        formatTimestamp(registry.installedVersionPublishedAt),
      ),
    );
  }
  if (registry.packageCreatedAt) {
    items.push(
      renderKvItem("Package created", formatTimestamp(registry.packageCreatedAt)),
    );
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
 * Render an HTML subsection showing registry maintenance signals for a dependency.
 *
 * @param maintenance - The dependency's maintenance block; may be `undefined` for older reports or skipped lookups.
 * @returns The HTML string for the "Maintenance" subsection, or an empty string when no lookup was attempted.
 */
function renderMaintenanceSection(
  maintenance: DependencyRecord["maintenance"] | undefined,
): string {
  if (!maintenance?.attempted) return "";
  const items = [
    renderKvItem("Status", getMaintenanceStatusLabel(maintenance.status)),
  ];
  if (maintenance.deprecated) {
    const scope = maintenance.deprecated.installedVersion
      ? "Installed version"
      : "Latest version";
    items.push(
      renderKvItem("Deprecated", scope, maintenance.deprecated.message),
    );
  }
  if (maintenance.repoArchived !== undefined) {
    items.push(
      renderKvItem(
        "Repository archived",
        yesNo(maintenance.repoArchived),
        maintenance.repoCheckedAt
          ? `Checked ${formatTimestamp(maintenance.repoCheckedAt, true)}`
          : undefined,
      ),
    );
  }
  if (maintenance.packageModifiedAt) {
    items.push(
      renderKvItem(
        "Last registry activity",
        formatTimestamp(maintenance.packageModifiedAt),
        typeof maintenance.monthsSinceModified === "number"
          ? formatMonthsAgo(maintenance.monthsSinceModified)
          : undefined,
      ),
    );
  }
  if (maintenance.repoPushedAt) {
    items.push(
      renderKvItem(
        "Last repository push",
        formatTimestamp(maintenance.repoPushedAt),
        typeof maintenance.monthsSinceRepoPush === "number"
          ? formatMonthsAgo(maintenance.monthsSinceRepoPush)
          : undefined,
      ),
    );
  }
  if (maintenance.latestVersion) {
    items.push(renderKvItem("Latest version", maintenance.latestVersion));
  }
  if (maintenance.fetchedAt) {
    items.push(
      renderKvItem(
        "Data fetched",
        formatTimestamp(maintenance.fetchedAt, true) +
          (maintenance.fromCache ? " (cached)" : ""),
      ),
    );
  }
  if (maintenance.error) {
    items.push(renderKvItem("Error", maintenance.error));
  }
  // Mirrors the status chip: amber statuses (unmaintained/stale/slowing) tint
  // too, so this section is not the odd one out now every other section does.
  const statusTone = getMaintenanceStatusTone(maintenance.status);
  const tone =
    statusTone === "red" || statusTone === "amber"
      ? subsectionTone(statusTone)
      : undefined;
  return renderSubsection(
    "Maintenance",
    '<div class="section-note">Conservative registry heuristics: "last registry activity" updates on any packument write, so age-based statuses under-flag rather than over-flag. When a repository push timestamp is also known, both surfaces must be quiet before a package escalates past "slowing". Review cues, not verdicts.</div>' +
      '<div class="kv-grid">' +
      items.join("") +
      "</div>",
    undefined,
    tone,
  );
}

const REPLACEMENT_TYPE_LABELS: Record<string, string> = {
  native: "Native platform functionality",
  documented: "Lighter community alternative",
  simple: "Small inline snippet",
};

/**
 * Render a "Replacement available" subsection for a dependency with a
 * community-suggested replacement. Returns an empty string when the
 * dependency has no suggestion, so reports without recommendations show
 * nothing.
 */
function renderReplacementSection(
  replacement: DependencyRecord["replacement"] | undefined,
): string {
  if (!replacement?.replacements?.length) return "";
  const items = [
    renderKvItem("Suggested", replacement.replacements.join(", ")),
    renderKvItem(
      "Replacement type",
      REPLACEMENT_TYPE_LABELS[replacement.type] || replacement.type,
    ),
  ];
  const docLink = replacement.docUrl
    ? '<div class="section-note"><a href="' +
      escapeHtml(replacement.docUrl) +
      '" target="_blank" rel="noopener noreferrer">Migration guidance for this replacement</a></div>'
    : "";
  const credit =
    '<div class="section-note">Suggestion from the community-maintained ' +
    '<a href="https://github.com/es-tooling/module-replacements" target="_blank" rel="noopener noreferrer">module-replacements</a> catalogue, ' +
    'part of the <a href="https://e18e.dev" target="_blank" rel="noopener noreferrer">e18e</a> ecosystem performance initiative. ' +
    "Guidance to review, not a drop-in instruction.</div>";
  return renderSubsection(
    "Replacement available",
    '<div class="kv-grid">' + items.join("") + "</div>" + docLink + credit,
    "Community-suggested lighter or native alternative",
    "opportunity",
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

function safeExternalUrl(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return undefined;
    parsed.username = "";
    parsed.password = "";
    return parsed.toString();
  } catch {
    return undefined;
  }
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
  const npmUrl = safeExternalUrl(links.npm);
  const repositoryUrl = safeExternalUrl(links.repository);
  const homepageUrl = safeExternalUrl(links.homepage);
  const issuesUrl = safeExternalUrl(links.issues);
  if (!npmUrl && !repositoryUrl && !homepageUrl && !issuesUrl) return "";
  if (npmUrl) {
    html +=
      '<a href="' +
      escapeHtml(npmUrl) +
      '" target="_blank" rel="noopener" class="package-link">' +
      icons.npm +
      "npm</a>";
  }

  if (repositoryUrl) {
    html +=
      '<a href="' +
      escapeHtml(repositoryUrl) +
      '" target="_blank" rel="noopener" class="package-link">' +
      icons.repo +
      "Repository</a>";
  }

  if (homepageUrl) {
    html +=
      '<a href="' +
      escapeHtml(homepageUrl) +
      '" target="_blank" rel="noopener" class="package-link">' +
      icons.homepage +
      "Homepage</a>";
  }

  if (issuesUrl) {
    html +=
      '<a href="' +
      escapeHtml(issuesUrl) +
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
    const referenceUrl = safeExternalUrl(adv.url);
    const referenceCell = referenceUrl
      ? '<a href="' +
        escapeHtml(referenceUrl) +
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

function renderDep(
  dep: DependencyRecord,
  supplyChainSignals?: SupplyChainSignal[],
): string {
  const normalizedSecurity = normalizeSecurity(dep);
  const securitySummary = normalizedSecurity.summary;
  const highestRisk = buildReportOverallRisk(
    dep as any,
    securitySummary,
    supplyChainSignals?.length || 0,
    supplyChainSignals as any,
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
// Per-dependency graph stats, computed lazily from the full graph the first
// time the list needs one. Two DIFFERENT questions live here:
// - subs:  unique packages beneath it (reachability — what depends on being
//          installed while it is);
// - frees: what removing it actually uninstalls (dominator footprint; 0 for
//          a direct dependency other packages still pull in).
interface DepGraphStats {
  subs: number;
  frees: number;
}
let depStatsByKey: Map<string, DepGraphStats> | null = null;
let depStatsBuilder: (() => Map<string, DepGraphStats>) | null = null;
function getDepStats(depKey: string): DepGraphStats | undefined {
  if (!depStatsByKey && depStatsBuilder) {
    depStatsByKey = depStatsBuilder();
  }
  return depStatsByKey?.get(depKey);
}
function getSubDepCount(depKey: string): number | undefined {
  return getDepStats(depKey)?.subs;
}
interface DupDependent {
  name: string;
  version: string;
  range: string | null;
}
interface DupVersion {
  version: string;
  direct: boolean;
  dependents: DupDependent[];
}
let dupGroupsByName: Map<string, DupVersion[]> | null = null;
let dupGroupsBuilder: (() => Map<string, DupVersion[]>) | null = null;
function getDuplicateGroup(name: string): DupVersion[] | undefined {
  if (!dupGroupsByName && dupGroupsBuilder) {
    dupGroupsByName = dupGroupsBuilder();
  }
  return dupGroupsByName?.get(name);
}

function formatByteSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} kB`;
  return `${bytes} B`;
}

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

  const workspaceListHtml = dep.usage.origins.workspaces?.length
    ? '<div class="micro-sublist"><div class="micro-subtitle">Workspaces</div>' +
      renderPackageList(dep.usage.origins.workspaces, 8) +
      "</div>"
    : "";

  const descriptionHtml = dep.package.description
    ? '<p class="dep-description"><span>Description: </span>' + escapeHtml(dep.package.description) + '</p>'
    : '';

  const overviewItems = [
    renderKvItem(
      "Dependency status",
      dep.usage.direct ? "Direct dependency" : "Transitive dependency",
    ),
    renderKvItem("Scope", scopeLabel(dep.usage.scope)),
    dep.usage.introduction
      ? renderKvItem("Introduced by", titleCaseValue(dep.usage.introduction))
      : "",
    dep.usage.runtimeImpact
      ? renderKvItem(
          "Runtime impact",
          runtimeImpactLabel(dep.usage.runtimeImpact),
        )
      : "",
    renderKvItem("Dependency depth", dep.usage.depth),
    (() => {
      const stats = getDepStats(`${dep.package.name}@${dep.package.version}`);
      if (!stats) return "";
      const freesLabel =
        dep.usage.direct && stats.frees === 0
          ? "Nothing (still required by other packages)"
          : stats.frees;
      const size = dep.package.installSize;
      const sizeRows = size
        ? renderKvItemHtml(
            "Install size (measured, uncompressed)",
            '<span class="kv-value">' +
              escapeHtml(
                `${formatByteSize(size.totalBytes)}${size.codeBytes > 0 ? ` (${formatByteSize(size.codeBytes)} code)` : ""}`,
              ) +
              " " +
              finePrintBtnHtml("size") +
              "</span>",
          ) +
          (typeof dep.package.fileCount === "number"
            ? renderKvItem("Files on disk", dep.package.fileCount)
            : "")
        : "";
      const group = getDuplicateGroup(dep.package.name);
      let dupRow = "";
      if (group && group.length >= 2) {
        const parts = group
          .filter((v) => v.version !== dep.package.version)
          .map((v) => {
            const via = v.dependents
              .slice(0, 3)
              .map((d) => `${d.name}${d.range ? ` (${d.range})` : ""}`)
              .join(", ");
            const extra = v.dependents.length > 3 ? ` +${v.dependents.length - 3}` : "";
            const why = via ? ` \u00b7 via ${via}${extra}` : v.direct ? " \u00b7 direct dependency" : "";
            return `${v.version}${why}`;
          });
        if (parts.length > 0) {
          dupRow = renderKvItem("Also installed as", parts.join("  ·  "));
        }
      }
      return (
        renderKvItem("Sub-dependencies", stats.subs) +
        renderKvItem("Removal frees", freesLabel) +
        sizeRows +
        dupRow
      );
    })(),
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

  const overviewGridHtml =
    '<div class="definition-grid">' + overviewItems.join("") + "</div>";
  const importTopFilesHtml = renderDetailList(
    "Top import locations",
    dep.usage.importUsage?.topFiles,
    5,
    "mono",
  );

  const overviewSection = renderSection(
    "Overview",
    undefined,
    overviewGridHtml + workspaceListHtml + importTopFilesHtml,
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
    undefined,
    subsectionTone(dep.compliance.licenseRisk),
  );

  const vulnTotal = reportVulnerabilityTotal(securitySummary);
  // Mirrors the chip strip: with no audit data this states what the report
  // holds instead of showing a green "no known vulnerabilities".
  const vulnUnchecked = vulnTotal === 0 && !auditCollectorAvailable;
  const vulnSummaryItems = [
    renderKvItemHtml(
      "Vulnerability status",
      renderRiskValue(
        vulnTotal === 0
          ? vulnUnchecked
            ? `None reported (${auditCoverageNote()})`
            : "No known vulnerabilities"
          : String(vulnTotal),
        vulnUnchecked ? "gray" : securitySummary.risk,
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
    '<div class="kv-grid">' + vulnSummaryItems.join("") + "</div>",
    vulnBreakdown ? vulnBreakdown : "",
    advisoriesTable
      ? advisoriesTable
      : "",
  ].join("");
  const vulnTone = subsectionTone(securitySummary.risk);
  const vulnBlock = renderSubsection(
    "Vulnerabilities",
    vulnBody,
    "Known security issues from npm audit",
    "vuln-block" + (vulnTone ? " " + vulnTone : ""),
  );

  const executionBlock = dep.execution
    ? renderExecutionSection(dep.execution)
    : "";
  const packagingBlock = renderPackagingSection(dep.packaging);
  const registryBlock = renderRegistryEnrichmentSection(dep.supplyChain?.registry);
  const maintenanceBlock = renderMaintenanceSection(dep.maintenance);
  const supplyChainBlock = renderSupplyChainSourceSection(supplyChainSignals);

  const riskBody = licenseBlock + vulnBlock + maintenanceBlock + executionBlock + packagingBlock + registryBlock + supplyChainBlock;
  const riskSection = renderSection(
    "Risk & Compliance",
    undefined,
    riskBody,
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
  if (dep.upgrade.risk) {
    currencyItems.push(
      renderKvItem(
        "Upgrade risk",
        getColumnCapitalize(dep.upgrade.risk),
        "Derived from outdated status and known blockers",
      ),
    );
  }
  const currencyBlock = renderSubsection(
    "Version",
    '<div class="section-note">Based on npm outdated findings and registry metadata.</div>' +
      '<div class="kv-grid">' +
      currencyItems.join("") +
      "</div>",
    undefined,
    subsectionTone(
      dep.upgrade.risk === "high"
        ? "red"
        : dep.upgrade.risk === "medium"
          ? "amber"
          : undefined,
    ),
  );

  // The Maintenance section (Risk & Compliance) supersedes this block when
  // it actually carries deprecation info; keep it for older report JSON and
  // for local-metadata deprecations whose registry lookup failed.
  const deprecatedBlock = dep.package.deprecated && !dep.maintenance?.deprecated
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
    undefined,
    dep.upgrade.blocksNodeMajor ? "caution" : undefined,
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
  const blockers = '<div class="subsection' + (dep.upgrade.blockers?.length ? " caution" : "") + '"><div class="subsection-header"><span class="subsection-title">Upgrade blockers</span></div>' +
    (dep.upgrade.blockers?.length
      ? '<ul class="bullet-list">' +
        dep.upgrade.blockers
          .map(
            (blocker) =>
              "<li>" + escapeHtml(blockerLabels[blocker] || blocker) + "</li>",
          )
          .join("") +
        "</ul>"
      : '<div class="status-row">No upgrade blockers detected</div>') +
    "</div>";

  const replacementBlock = renderReplacementSection(dep.replacement);
  const upgradeSection = renderSection(
    "Upgrade & Change Impact",
    "Currency, constraints, and blast radius",
    replacementBlock +
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
    descriptionHtml,
    buildStatusChips(dep, securitySummary, licenseText),
    renderKeyPoints(
      buildReportKeyPoints(dep as any, securitySummary, supplyChainSignals as any),
    ),
    overviewSection,
    riskSection,
    upgradeSection,
    declaredSection,
    renderSection(
      "Removal preview",
      "What deleting this package would actually free",
      '<div class="list-sim" data-sim-key="' +
        escapeHtml(`${dep.package.name}@${dep.package.version}`) +
        '"></div>',
    ),
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
  auditCollectorStatus = report.scanStatus?.collectors.audit ?? "available";
  auditCollectorAvailable = auditCollectorStatus === "available";
  const container = document.getElementById("dependency-list")!;
  const summaryEl = document.getElementById("results-summary")!;
  const scanStatusBanner = document.getElementById("scan-status-banner");
  if (scanStatusBanner && report.scanStatus?.warnings.length) {
    scanStatusBanner.hidden = false;
    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.className = "scan-status-dismiss";
    dismiss.setAttribute("aria-label", "Dismiss scan status notice");
    dismiss.textContent = "×";
    dismiss.addEventListener("click", () => {
      scanStatusBanner.hidden = true;
    });
    scanStatusBanner.appendChild(dismiss);
    const heading = document.createElement("strong");
    heading.textContent = report.scanStatus.complete
      ? "Some analysis was intentionally skipped"
      : "Scan evidence is incomplete";
    scanStatusBanner.appendChild(heading);
    const list = document.createElement("ul");
    report.scanStatus.warnings.slice(0, 8).forEach((warning) => {
      const item = document.createElement("li");
      item.textContent = warning.length > 300 ? `${warning.slice(0, 297)}…` : warning;
      list.appendChild(item);
    });
    scanStatusBanner.appendChild(list);
  }

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
    maintenanceConcerns: document.getElementById(
      "maintenance-concerns",
    ) as HTMLInputElement | null,
    licenseIssues: document.getElementById(
      "license-issues",
    ) as HTMLInputElement | null,
    upgradeBlockers: document.getElementById(
      "upgrade-blockers",
    ) as HTMLInputElement | null,
    hasReplacement: document.getElementById(
      "has-replacement",
    ) as HTMLInputElement | null,
    noImports: document.getElementById(
      "no-imports",
    ) as HTMLInputElement | null,
    duplicateVersions: document.getElementById(
      "duplicate-versions",
    ) as HTMLInputElement | null,
    hasReplacementWrap: document.getElementById(
      "has-replacement-wrap",
    ) as HTMLElement | null,
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
    maintenanceConcernsLabel: document.getElementById(
      "maintenance-concerns-label",
    ) as HTMLElement | null,
    licenseIssuesLabel: document.getElementById(
      "license-issues-label",
    ) as HTMLElement | null,
    upgradeBlockersLabel: document.getElementById(
      "upgrade-blockers-label",
    ) as HTMLElement | null,
    hasReplacementLabel: document.getElementById(
      "has-replacement-label",
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
    graphModeSwitch: document.getElementById(
      "graph-mode-switch",
    ) as HTMLElement | null,
    graphAltHost: document.getElementById(
      "graph-alt-host",
    ) as HTMLElement | null,
    graphStatusLine: document.getElementById(
      "graph-status-line",
    ) as HTMLElement | null,
    graphKey: document.getElementById("graph-key") as HTMLElement | null,
    graphSearch: document.getElementById(
      "graph-search",
    ) as HTMLInputElement | null,
    graphSearchResults: document.getElementById(
      "graph-search-results",
    ) as HTMLElement | null,
    graphDossier: document.getElementById(
      "graph-dossier",
    ) as HTMLElement | null,
    graphSidePanel: document.getElementById(
      "graph-side-panel",
    ) as HTMLElement | null,
    graphFilterRuntime: document.getElementById(
      "graph-filter-runtime",
    ) as HTMLButtonElement | null,
    graphFilterDev: document.getElementById(
      "graph-filter-dev",
    ) as HTMLButtonElement | null,
    graphFilterSub: document.getElementById(
      "graph-filter-sub",
    ) as HTMLButtonElement | null,
    graphFilterDepth: document.getElementById(
      "graph-filter-depth",
    ) as HTMLSelectElement | null,
    reportFooter: document.querySelector(
      ".report-footer",
    ) as HTMLElement | null,
  };

  // Sorting state - "name" is the default (Package name ascending)
  let sortColumn = "name";
  let sortAscending = true;
  let graphView: GraphViewHandle | null = null;
  let graphInitialized = false;
  let graphModes: GraphModesHandle | null = null;

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

    // "Runtime", not "Production": production policies cover runtime AND
    // optional scopes, and this filter selects exactly one scope value.
    const scopeLabels: Record<string, string> = {
      all: "All",
      runtime: "Runtime",
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
    if (controls.maintenanceConcernsLabel)
      controls.maintenanceConcernsLabel.textContent = formatCount(
        "Maintenance concerns",
        countBy(hasMaintenanceConcern),
      );
    if (controls.licenseIssuesLabel)
      controls.licenseIssuesLabel.textContent = formatCount(
        "Licence issues",
        countBy(hasLicenseIssue),
      );
    if (controls.upgradeBlockersLabel)
      controls.upgradeBlockersLabel.textContent = formatCount(
        "Upgrade blockers",
        countBy(hasUpgradeBlocker),
      );
    // The replacement filter only exists in the UI when the scan actually
    // matched something against the e18e catalogue.
    const replacementCount = countBy(hasReplacementSuggestion);
    if (controls.hasReplacementWrap) {
      controls.hasReplacementWrap.hidden = replacementCount === 0;
    }
    if (controls.hasReplacementLabel && replacementCount > 0)
      controls.hasReplacementLabel.textContent = formatCount(
        "Has replacement suggestion",
        replacementCount,
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

  /**
   * Populate the header "scan at a glance" stat chips from the loaded report.
   *
   * Counts are computed client-side in one pass so the header works for any
   * report version; chips whose source data is absent (older reports or
   * offline scans) are hidden rather than shown as zero.
   */
  function populateHeaderStats(): void {
    const statsRoot = document.getElementById("header-stats");
    if (!statsRoot) return;

    let vulnerable = 0;
    let maintenanceConcernCount = 0;
    let maintenanceDeprecated = 0;
    let maintenanceArchived = 0;
    let maintenanceDataSeen = false;
    let licenseIssues = 0;
    let licenseHighRisk = 0;
    let blockers = 0;
    let blocksNodeMajor = 0;
    let replacements = 0;
    let directReplacements = 0;
    // One advisory reaches every package above it in the chain (the `via`
    // expansion in the aggregator), so the same id lands on several records.
    // Counting distinct ids is what makes this comparable to a scanner's
    // "unique vulnerabilities" rather than "affected packages".
    const advisoryIds = new Set<string>();
    allDependencies.forEach((dep) => {
      if (hasVulnerabilities(dep)) vulnerable += 1;
      for (const advisory of normalizeSecurity(dep).advisories || []) {
        if (advisory?.id) advisoryIds.add(String(advisory.id));
      }
      if (hasReplacementSuggestion(dep)) {
        replacements += 1;
        if (dep.usage.direct) directReplacements += 1;
      }
      if (dep.maintenance?.attempted) maintenanceDataSeen = true;
      if (hasMaintenanceConcern(dep)) {
        maintenanceConcernCount += 1;
        const status = dep.maintenance?.status;
        if (status === "deprecated") maintenanceDeprecated += 1;
        if (status === "archived") maintenanceArchived += 1;
      }
      if (hasLicenseIssue(dep)) {
        licenseIssues += 1;
        if (dep.compliance.licenseRisk === "red") licenseHighRisk += 1;
      }
      if (hasUpgradeBlocker(dep)) {
        blockers += 1;
        if (dep.upgrade.blocksNodeMajor) blocksNodeMajor += 1;
      }
    });
    // Reports whose audit format carried severity counts but no advisory
    // detail would otherwise headline "0 vulnerabilities" beside a non-zero
    // package count, so those fall back to the package figure.
    const advisoryCount = advisoryIds.size;
    const advisoryDetailMissing = advisoryCount === 0 && vulnerable > 0;

    const setChip = (
      id: string,
      value: number,
      tone?: "red" | "amber",
      title?: string,
      sub?: string,
    ): void => {
      const chip = document.getElementById(id);
      if (!chip) return;
      const valueEl = chip.querySelector("strong");
      if (valueEl) valueEl.textContent = String(value);
      chip.classList.remove("red", "amber");
      if (tone && value > 0) chip.classList.add(tone);
      if (title) chip.title = title;
      const subEl = chip.querySelector<HTMLElement>(".stat-sub");
      if (subEl) {
        subEl.textContent = sub || "";
        subEl.hidden = !sub;
      }
    };
    const plural = (
      count: number,
      singular: string,
      pluralForm = `${singular}s`,
    ): string =>
      `${count.toLocaleString()} ${count === 1 ? singular : pluralForm}`;

    setChip(
      "stat-total",
      report.summary.dependencyCount,
      undefined,
      `${report.summary.directCount} direct, ${report.summary.transitiveCount} transitive`,
      `${report.summary.directCount.toLocaleString()} direct`,
    );
    setChip(
      "stat-vulnerable",
      advisoryDetailMissing ? vulnerable : advisoryCount,
      "red",
      advisoryDetailMissing
        ? "Dependencies with known vulnerabilities (click to filter)"
        : `${plural(advisoryCount, "distinct advisory", "distinct advisories")} affecting ${plural(vulnerable, "dependency", "dependencies")} (click to filter)`,
      // Nothing to break down on a clean report, and "in 0 packages" beside a
      // zero headline is pure noise.
      advisoryDetailMissing || vulnerable === 0
        ? undefined
        : `in ${plural(vulnerable, "package")}`,
    );
    if (advisoryDetailMissing) {
      // The fallback headlines affected packages, so the static label would
      // otherwise name a quantity this chip is not showing.
      const vulnLabel = document.querySelector("#stat-vulnerable .meta-label");
      if (vulnLabel) vulnLabel.textContent = "Vulnerable";
    }
    const markChipUnknown = (id: string, status: string, label: string): void => {
      const chip = document.getElementById(id) as HTMLButtonElement | null;
      if (!chip) return;
      chip.hidden = false;
      chip.disabled = true;
      chip.classList.remove("red", "amber");
      const valueEl = chip.querySelector("strong");
      if (valueEl) valueEl.textContent = "?";
      // The chip may already carry a sub-line from setChip; a breakdown of a
      // figure that was never collected is worse than none.
      const subEl = chip.querySelector<HTMLElement>(".stat-sub");
      if (subEl) {
        subEl.textContent = "";
        subEl.hidden = true;
      }
      chip.title = `${label} is unknown because its collector is ${status}`;
    };
    const auditStatus = report.scanStatus?.collectors.audit;
    if (auditStatus && auditStatus !== "available") {
      markChipUnknown("stat-vulnerable", auditStatus, "Vulnerability status");
    }
    setChip(
      "stat-license",
      licenseIssues,
      "amber",
      "Dependencies with licence review flags (click to filter)",
      licenseHighRisk > 0 ? `${licenseHighRisk.toLocaleString()} high risk` : undefined,
    );
    setChip(
      "stat-blockers",
      blockers,
      "amber",
      "Dependencies with upgrade blockers (click to filter)",
      blocksNodeMajor > 0
        ? `${blocksNodeMajor.toLocaleString()} Node major`
        : undefined,
    );
    // Only surfaced when the scan matched at least one dependency against
    // the e18e module-replacements catalogue.
    const replacementsChip = document.getElementById(
      "stat-replacements",
    ) as HTMLButtonElement | null;
    if (replacementsChip) {
      if (replacements === 0) {
        replacementsChip.hidden = true;
      } else {
        replacementsChip.hidden = false;
        setChip(
          "stat-replacements",
          replacements,
          undefined,
          "Dependencies with community-suggested replacements from e18e (click to filter)",
          directReplacements > 0
            ? `${directReplacements.toLocaleString()} direct`
            : undefined,
        );
      }
    }
    // Name the single status when only one occurs, and fall back to the
    // umbrella when both do. Spelling both out was longer than the "N
    // deprecated or archived" this replaced, which defeated the point.
    const maintenanceSub =
      maintenanceDeprecated > 0 && maintenanceArchived > 0
        ? `${(maintenanceDeprecated + maintenanceArchived).toLocaleString()} end of life`
        : maintenanceDeprecated > 0
          ? `${maintenanceDeprecated.toLocaleString()} deprecated`
          : maintenanceArchived > 0
            ? `${maintenanceArchived.toLocaleString()} archived`
            : undefined;
    const maintenanceChip = document.getElementById("stat-maintenance");
    if (maintenanceChip) {
      const maintenanceStatus = report.scanStatus?.collectors.maintenance;
      if (maintenanceStatus && maintenanceStatus !== "available") {
        markChipUnknown("stat-maintenance", maintenanceStatus, "Maintenance status");
      } else if (!maintenanceDataSeen) {
        maintenanceChip.hidden = true;
      } else {
        setChip(
          "stat-maintenance",
          maintenanceConcernCount,
          maintenanceDeprecated + maintenanceArchived > 0 ? "red" : "amber",
          "Deprecated, archived, unmaintained, or stale dependencies (click to filter)",
          maintenanceSub,
        );
      }
    }

    statsRoot.addEventListener("click", (event) => {
      const button = (event.target as HTMLElement).closest<HTMLButtonElement>(
        "[data-stat-filter]",
      );
      if (!button) return;
      if (button.disabled) return;
      const targets: Record<string, HTMLInputElement | null | undefined> = {
        "has-vulns": controls.hasVulns,
        "maintenance-concerns": controls.maintenanceConcerns,
        "no-imports": controls.noImports,
        "duplicate-versions": controls.duplicateVersions,
        "license-issues": controls.licenseIssues,
        "upgrade-blockers": controls.upgradeBlockers,
        "has-replacement": controls.hasReplacement,
      };
      const control = targets[button.dataset.statFilter || ""];
      if (!control) return;
      // Stat tiles are shortcuts, not additive filters: clear every other
      // filter (including search), then toggle just this one.
      const wasChecked = control.checked;
      controls.search.value = "";
      resetNonSearchFilters();
      control.checked = !wasChecked;
      control.dispatchEvent(new Event("change"));
    });
  }
  populateHeaderStats();

  const depByKey = new Map<string, DependencyRecord>();
  allDependencies.forEach((dep) => {
    depByKey.set(getDepKey(dep.package.name, dep.package.version), dep);
  });
  const knownDepKeys = new Set(depByKey.keys());
  // Installed-version counts per package name, for the duplicate-versions
  // highlight ("lodash appears 3×").
  const duplicateVersionNames = new Map<string, number>();
  allDependencies.forEach((dep) => {
    duplicateVersionNames.set(
      dep.package.name,
      (duplicateVersionNames.get(dep.package.name) ?? 0) + 1,
    );
  });
  // Positive import evidence ("imported in N files") is valid whenever the
  // scan ran at all, but the NEGATIVE claim ("no imports found") needs a
  // complete scan — under a partial one, a missing record may just mean the
  // workspace whose scan failed was the importer.
  const importsCollectorRan =
    report.scanStatus?.collectors?.imports === "available" ||
    report.scanStatus?.collectors?.imports === "partial";
  const importsEvidenceComplete =
    report.scanStatus?.collectors?.imports === "available";
  if (!importsEvidenceComplete) {
    const reason = importsCollectorRan
      ? "Import scanning was incomplete for this report"
      : "Import scanning did not run for this report";
    const unusedChip = document.getElementById(
      "graph-hl-unused",
    ) as HTMLButtonElement | null;
    if (unusedChip) {
      unusedChip.disabled = true;
      unusedChip.title = reason;
    }
    if (controls.noImports) {
      controls.noImports.disabled = true;
      controls.noImports.title = reason;
      const label = controls.noImports.closest("label");
      if (label) label.title = reason;
    }
  }
  // One graph dataset and one default-filters model per workspace, shared
  // by the list view, the graph views, and the removal simulator — so the
  // simulation memos are computed once no matter where you look first.
  let sharedDatasetMemo: ReturnType<typeof adaptDataset> | null = null;
  const getSharedDataset = (): ReturnType<typeof adaptDataset> =>
    (sharedDatasetMemo ??= adaptDataset(report, knownDepKeys, resolveDepKey));
  const listSimProjectName =
    (report.project as { name?: string } | undefined)?.name ||
    report.project?.projectDir?.split("/").filter(Boolean).pop() ||
    "project";
  const fullModels = new Map<string, VizModel>();
  const getFullModel = (workspaceName: string): VizModel => {
    let m = fullModels.get(workspaceName);
    if (!m) {
      m = buildVizModel(getSharedDataset(), workspaceName, listSimProjectName);
      fullModels.set(workspaceName, m);
    }
    return m;
  };
  depStatsByKey = null;
  depStatsBuilder = () => {
    const dataset = getSharedDataset();
    const slugs = Object.keys(dataset.dependencies);
    const indexOf = new Map(slugs.map((slug, index) => [slug, index]));
    const out = slugs.map((slug) =>
      (dataset.dependencies[slug].dependencies || [])
        .map((child) => indexOf.get(child))
        .filter((index): index is number => index !== undefined),
    );
    const counts = computeReachCounts(slugs.length, out);
    // Removal impact over the whole project: every workspace's direct
    // dependencies are the roots. Same semantics as the graph dossier —
    // a direct dep other packages still pull in frees nothing.
    const rootSet = new Set<number>();
    for (const workspace of dataset.workspaces) {
      for (const slug of [
        ...workspace.directDependencies,
        ...workspace.directDevDependencies,
      ]) {
        const index = indexOf.get(slug);
        if (index !== undefined) rootSet.add(index);
      }
    }
    const dom = buildDomTree(slugs.length, out, [...rootSet]);
    const depsIn: number[][] = Array.from({ length: slugs.length }, () => []);
    out.forEach((kids, from) => {
      for (const to of kids) if (to !== from) depsIn[to].push(from);
    });
    const dominatedBy = (node: number, target: number): boolean => {
      let cur = node;
      let guard = 0;
      while (cur >= 0 && guard < 100_000) {
        if (cur === target) return true;
        cur = dom.idom[cur];
        guard += 1;
      }
      return false;
    };
    const map = new Map<string, DepGraphStats>();
    slugs.forEach((slug, index) => {
      let frees = dom.exclusiveCount[index];
      if (rootSet.has(index)) {
        const kept = depsIn[index].some((pred) => !dominatedBy(pred, index));
        if (kept) frees = 0;
      }
      map.set(slug, { subs: Math.max(0, counts[index] - 1), frees });
    });
    return map;
  };
  dupGroupsByName = null;
  dupGroupsBuilder = () => {
    const groups = new Map<string, DupVersion[]>();
    for (const dep of allDependencies) {
      if ((duplicateVersionNames.get(dep.package.name) ?? 0) < 2) continue;
      const list = groups.get(dep.package.name) ?? [];
      list.push({
        version: dep.package.version,
        direct: dep.usage.direct,
        dependents: [],
      });
      groups.set(dep.package.name, list);
    }
    // Who links to which installed version, with the declared range —
    // subDeps entries carry [range, resolvedVersion].
    for (const parent of allDependencies) {
      const sections = parent.graph.subDeps;
      if (!sections) continue;
      for (const section of [sections.dep, sections.dev, sections.opt, sections.peer]) {
        if (!section) continue;
        for (const [childName, entry] of Object.entries(section)) {
          const group = groups.get(childName);
          if (!group || !Array.isArray(entry)) continue;
          const [range, resolved] = entry;
          // resolved is a dep key ("name@version"), not a bare version;
          // normalise through resolveDepKey so npm aliases still match.
          const resolvedKey = resolved
            ? (resolveDepKey(resolved) ?? resolved)
            : null;
          const target = resolvedKey
            ? group.find((v) => `${childName}@${v.version}` === resolvedKey)
            : undefined;
          if (target) {
            target.dependents.push({
              name: parent.package.name,
              version: parent.package.version,
              range: typeof range === "string" ? range : null,
            });
          }
        }
      }
    }
    for (const list of groups.values()) {
      list.sort((a, b) => b.dependents.length - a.dependents.length);
    }
    return groups;
  };
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
      // The removal preview fills in as soon as the card opens — the
      // simulation is memoised on the shared model, so this is instant
      // after the first look at a workspace.
      const simHolder = detailsBody.querySelector<HTMLElement>(".list-sim");
      const simKey = simHolder?.dataset.simKey;
      if (simHolder && simKey) runListSimulation(simHolder, simKey);
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
    const maintenanceConcerns = controls.maintenanceConcerns?.checked ?? false;
    const licenseIssuesOnly = controls.licenseIssues?.checked ?? false;
    const upgradeBlockersOnly = controls.upgradeBlockers?.checked ?? false;
    const replacementOnly = controls.hasReplacement?.checked ?? false;
    const noImportsOnly = controls.noImports?.checked ?? false;
    const duplicatesOnly = controls.duplicateVersions?.checked ?? false;

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
      if (maintenanceConcerns && !hasMaintenanceConcern(dep)) return false;
      if (licenseIssuesOnly && !hasLicenseIssue(dep)) return false;
      if (upgradeBlockersOnly && !hasUpgradeBlocker(dep)) return false;
      if (replacementOnly && !hasReplacementSuggestion(dep)) return false;
      if (
        noImportsOnly &&
        !(
          importsEvidenceComplete &&
          dep.usage.direct &&
          !(dep.usage.importUsage?.fileCount ?? 0)
        )
      )
        return false;
      if (
        duplicatesOnly &&
        (duplicateVersionNames.get(dep.package.name) ?? 0) < 2
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
    if (controls.maintenanceConcerns) controls.maintenanceConcerns.checked = false;
    if (controls.licenseIssues) controls.licenseIssues.checked = false;
    if (controls.upgradeBlockers) controls.upgradeBlockers.checked = false;
    if (controls.hasReplacement) controls.hasReplacement.checked = false;
    if (controls.noImports) controls.noImports.checked = false;
    if (controls.duplicateVersions) controls.duplicateVersions.checked = false;
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
    if (controls.maintenanceConcerns?.checked) {
      chips.push({
        id: "maintenance-concerns",
        label: "Maintenance concerns",
        remove: () => {
          if (controls.maintenanceConcerns) controls.maintenanceConcerns.checked = false;
        },
      });
    }
    if (controls.licenseIssues?.checked) {
      chips.push({
        id: "license-issues",
        label: "Licence issues",
        remove: () => {
          if (controls.licenseIssues) controls.licenseIssues.checked = false;
        },
      });
    }
    if (controls.noImports?.checked) {
      chips.push({
        id: "no-imports",
        label: "No imports found",
        remove: () => {
          if (controls.noImports) controls.noImports.checked = false;
        },
      });
    }
    if (controls.duplicateVersions?.checked) {
      chips.push({
        id: "duplicate-versions",
        label: "Duplicate versions",
        remove: () => {
          if (controls.duplicateVersions) controls.duplicateVersions.checked = false;
        },
      });
    }
    if (controls.upgradeBlockers?.checked) {
      chips.push({
        id: "upgrade-blockers",
        label: "Upgrade blockers",
        remove: () => {
          if (controls.upgradeBlockers) controls.upgradeBlockers.checked = false;
        },
      });
    }
    if (controls.hasReplacement?.checked) {
      chips.push({
        id: "has-replacement",
        label: "Has replacement suggestion",
        remove: () => {
          if (controls.hasReplacement) controls.hasReplacement.checked = false;
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
    } else if (sortColumn === "subdeps") {
      // Ascending like every other numeric key, so the direction arrow keeps
      // its meaning; flip the arrow for heaviest-first.
      const countOf = (dep: DependencyRecord): number =>
        getSubDepCount(`${dep.package.name}@${dep.package.version}`) ?? -1;
      sorted.sort((a, b) => countOf(a) - countOf(b));
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
    // Built with DOM nodes rather than innerHTML so no report- or
    // control-derived text is ever parsed as markup.
    const shownEl = document.createElement("strong");
    shownEl.textContent = String(deps.length);
    const totalEl = document.createElement("strong");
    totalEl.textContent = String(totalCount);
    summaryEl.replaceChildren("Showing ", shownEl, " of ", totalEl, " dependencies");
    if ((controls.workspace?.value || "all") !== "all") {
      const workspaceEl = document.createElement("strong");
      workspaceEl.textContent = controls.workspace.value;
      summaryEl.append(" in ", workspaceEl);
    }

    if (deps.length === 0) {
      container.innerHTML =
        '<div class="empty-state"><div class="empty-state-icon">📦</div><div class="empty-state-text">No dependencies match your filters</div></div>';
      return;
    }

    container.innerHTML = deps
      .map((dep) =>
        renderDep(
          dep,
          supplyChainSignalsByKey.get(
            getDepKey(dep.package.name, dep.package.version),
          ),
        ),
      )
      .join("");
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
      controls.graphCanvasShell,
    );
  }

  let currentView: "list" | "graph" = "list";
  let applyingRoute = false;
  let routerReady = false;
  let lastSyncedHash = "";
  let routeExpandedKey: string | null = null;
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
    currentView = view;
    if (isList) {
      graphModes?.exitFullscreen();
      graphView?.setActive(false);
      routeSync(true);
      return;
    }
    if (!graphInitialized) {
      // Init restores the persisted layout, which fires onRouteChange while
      // the graphModes variable is still unassigned; buildRouteHash would
      // serialise the list route and push a spurious entry. Save/restore so
      // an outer applyRouteFromHash guard is never released early.
      const wasApplyingRoute = applyingRoute;
      applyingRoute = true;
      // Small brand mark at the head of the graph toolbar. Cloned from the
      // header logo with its <defs> stripped: the gradient/style definitions
      // stay unique in the document and resolve from the original.
      const overlayTop = document.querySelector(".graph-overlay-top");
      const headerLogo = document.querySelector(".top-header svg.logo");
      if (overlayTop && headerLogo && !overlayTop.querySelector(".graph-logo")) {
        const brand = headerLogo.cloneNode(true) as SVGElement;
        brand.querySelector("defs")?.remove();
        brand.classList.remove("logo");
        brand.classList.add("graph-logo");
        brand.setAttribute("aria-hidden", "true");
        overlayTop.insertBefore(brand, overlayTop.firstChild);
      }
      graphView = initGraphView({
        report,
        knownDepKeys,
        resolveDepKey,
        workspaceSelect: controls.graphWorkspaceSelect as HTMLSelectElement,
        workspaceWrap: controls.graphWorkspaceWrap as HTMLElement,
        controlsRoot: controls.graphControls as HTMLElement,
        canvas: controls.graphCanvas as HTMLCanvasElement,
        canvasHost: controls.graphCanvasShell as HTMLElement,
        onOpenList: (slug: string) => {
          openListFromGraph(slug);
        },
        getImpactWeight: (slug: string, workspaceName: string) => {
          const m = getFullModel(workspaceName || "root");
          const idx = m.indexOfSlug.get(slug);
          return idx === undefined ? 1 : m.domTree().exclusiveCount[idx];
        },
        onSelect: (slug: string | null) => {
          graphModes?.handleClassicSelect(slug);
        },
        getFilters: () => graphModes?.filters() ?? DEFAULT_GRAPH_FILTERS,
        isNodeDimmed: (slug: string) =>
          graphModes?.isNameDimmed(slug) ?? false,
      });
      graphView.initGraphView();
      graphInitialized = true;
      if (
        controls.graphModeSwitch &&
        controls.graphAltHost &&
        controls.graphStatusLine &&
        controls.graphSearch &&
        controls.graphSearchResults &&
        controls.graphDossier &&
        controls.graphSidePanel &&
        controls.graphWorkspaceSelect
      ) {
        graphModes = initGraphModes({
          dataset: getSharedDataset(),
          getSharedModel: (workspace: string) => getFullModel(workspace),
          projectName:
            (report.project as { name?: string } | undefined)?.name ||
            report.project?.projectDir?.split("/").filter(Boolean).pop() ||
            "project",
          altHost: controls.graphAltHost,
          modeSwitch: controls.graphModeSwitch,
          statusLine: controls.graphStatusLine,
          searchInput: controls.graphSearch,
          searchResults: controls.graphSearchResults,
          dossier: controls.graphDossier,
          sidePanel: controls.graphSidePanel,
          keyEl: controls.graphKey,
          workspaceSelect: controls.graphWorkspaceSelect,
          classicOnly: [controls.graphControls].filter(
            (node): node is HTMLElement => Boolean(node),
          ),
          getClassicHandle: () => graphView,
          onRouteChange: () => routeSync(true),
          filterRuntime: controls.graphFilterRuntime,
          filterDev: controls.graphFilterDev,
          filterSub: controls.graphFilterSub,
          filterDepth: controls.graphFilterDepth,
          getReplacement: (slug: string) => {
            const key = resolveDepKey(slug);
            const dep = key ? depByKey.get(key) : undefined;
            if (!dep?.replacement?.replacements?.length) return null;
            return dep.replacement;
          },
          getPackageExtras: (slug: string) => {
            const key = resolveDepKey(slug);
            const dep = key ? depByKey.get(key) : undefined;
            if (!dep) return {};
            const size = dep.package.installSize;
            const platform = dep.package.platform;
            // npm checkPlatform semantics: "!win32" entries form a blocklist,
            // plain entries an allowlist; a negation-only list allows the rest.
            const platformMiss = (list: string[] | undefined, value: string | undefined): boolean => {
              if (!list?.length || !value) return false;
              const allowed = list.filter((entry) => !entry.startsWith("!"));
              if (list.includes(`!${value}`)) return true;
              return allowed.length > 0 && !allowed.includes(value);
            };
            let platformNote: string | undefined;
            if (platform && (platform.os?.length || platform.cpu?.length)) {
              const here = report.environment;
              const osMiss = platformMiss(platform.os, here?.platform);
              const cpuMiss = platformMiss(platform.cpu, here?.arch);
              const target = [
                ...(platform.os ?? []),
                ...(platform.cpu ?? []),
              ].join("/");
              platformNote =
                osMiss || cpuMiss
                  ? `built for ${target}, not this machine`
                  : `platform-specific: ${target}`;
            }
            return {
              ...(size ? { sizeBytes: size.totalBytes, codeBytes: size.codeBytes } : {}),
              ...(platformNote ? { platformNote } : {}),
              ...(importsCollectorRan &&
              !dep.usage.direct &&
              (dep.usage.importUsage?.fileCount ?? 0) > 0
                ? { phantom: true }
                : {}),
              ...((dep.usage.importUsage?.fileCount ?? 0) > 0
                ? { importFileCount: dep.usage.importUsage!.fileCount }
                : importsEvidenceComplete
                  ? { importFileCount: 0 }
                  : {}),
            };
          },
          highlightMatch: (slug: string, kind: string) => {
            const key = resolveDepKey(slug);
            const dep = key ? depByKey.get(key) : undefined;
            if (!dep) return false;
            switch (kind) {
              case "vuln":
                return (
                  getColumnHighestSeverity(
                    getColumnNormalizeSecurity(dep).summary,
                  ) !== "none"
                );
              case "maintenance":
                return hasMaintenanceConcern(dep);
              case "replacement":
                return hasReplacementSuggestion(dep);
              case "license":
                return hasLicenseIssue(dep);
              case "blocker":
                return hasUpgradeBlocker(dep);
              case "unused":
                // Direct deps only (project source rarely imports transitive
                // packages directly), and only when the import scan actually
                // ran — otherwise everything would light up as "unused".
                return (
                  importsEvidenceComplete &&
                  dep.usage.direct &&
                  !(dep.usage.importUsage?.fileCount ?? 0)
                );
              case "duplicate":
                return (duplicateVersionNames.get(dep.package.name) ?? 0) > 1;
              default:
                return false;
            }
          },
          onOpenList: (slug: string) => {
            openListFromGraph(slug);
          },
        });
        // The classic graph was built before `graphModes` was assigned, so its
        // getFilters() saw the defaults; rebuild it if persisted state differs.
        if (
          JSON.stringify(graphModes.filters()) !==
          JSON.stringify(DEFAULT_GRAPH_FILTERS)
        ) {
          graphView?.refreshFilters();
        }
      }
      applyingRoute = wasApplyingRoute;
    }
    if (!graphModes || graphModes.mode() === "graph") {
      graphView?.setActive(true);
      graphView?.requestRender();
    } else {
      graphModes.refresh();
    }
    routeSync(true);
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
    if (depByKey.has(slug)) routeExpandedKey = slug;
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
    controls.maintenanceConcerns,
    controls.licenseIssues,
    controls.upgradeBlockers,
    controls.hasReplacement,
    controls.workspace,
    controls.licensePermissive,
    controls.licenseWeakCopyleft,
    controls.licenseStrongCopyleft,
    controls.licenseUnknown,
    controls.noImports,
    controls.duplicateVersions,
  ];
  const handleFilterControlChange = (pushRoute = true): void => {
    // User-driven filtering should return to normal behavior.
    forcedVisibleDepKeys.clear();
    renderList();
    // Search keystrokes replace the current history entry; discrete filter
    // changes get their own entry so back/forward walks them.
    routeSync(pushRoute);
  };

  filterControls.forEach((ctrl) => {
    if (!ctrl) return;
    const isSearch = ctrl === controls.search;
    // One event per control: text inputs and checkboxes both fire input AND
    // change — double-binding rendered the list twice per interaction.
    ctrl.addEventListener(isSearch ? "input" : "change", () =>
      handleFilterControlChange(!isSearch),
    );
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
        routeExpandedKey = depKey;
      } else {
        openDepKeys.delete(depKey);
        if (routeExpandedKey === depKey) routeExpandedKey = null;
      }
      routeSync(true);
    },
    true,
  );

  // ----- list-view removal simulator -----------------------------------
  // Same maths as the graph dossier's summary, computed against the shared
  // full per-workspace models; rendered inline in the card as it opens.
  function runListSimulation(holder: HTMLElement, simKey: string): void {
    const dataset = getSharedDataset();
    if (!dataset.dependencies[simKey]) {
      // Not in the dependency graph at all: don't build every workspace's
      // model just to discover that.
      holder.textContent = "";
      const note = document.createElement("p");
      note.className = "list-sim-empty";
      note.textContent =
        "Not part of any workspace dependency graph, so nothing to simulate.";
      holder.appendChild(note);
      return;
    }
    // The package may only exist in some workspaces' graphs. Try the root
    // workspace first — it is the graph view's default, so the two views
    // quote the same numbers — then the named workspaces (they are sorted
    // alphabetically in the dataset).
    let model: VizModel | null = null;
    let index = -1;
    const ordered = [
      ...dataset.workspaces.filter((w) => w.name === "root"),
      ...dataset.workspaces.filter((w) => w.name !== "root"),
    ];
    for (const ws of ordered) {
      const m = getFullModel(ws.name);
      const idx = m.indexOfSlug.get(simKey);
      if (idx !== undefined) {
        model = m;
        index = idx;
        break;
      }
    }
    holder.textContent = "";
    if (!model || index < 0) {
      const note = document.createElement("p");
      note.className = "list-sim-empty";
      note.textContent =
        "Not part of any workspace dependency graph, so nothing to simulate.";
      holder.appendChild(note);
      return;
    }
    const sim = model.simulateRemoval(index);
    let freedBytes = 0;
    let sizedCount = 0;
    let vulns = 0;
    let licenses = 0;
    let maint = 0;
    for (const f of sim.freed) {
      const key = resolveDepKey(f.slug);
      const dep = key ? depByKey.get(key) : undefined;
      if (!dep) continue;
      if (dep.package.installSize) {
        freedBytes += dep.package.installSize.totalBytes;
        sizedCount += 1;
      }
      if (hasVulnerabilities(dep)) vulns += 1;
      if (hasLicenseIssue(dep)) licenses += 1;
      if (hasMaintenanceConcern(dep)) maint += 1;
    }
    const panel = document.createElement("div");
    panel.className = "list-sim-panel";
    const addP = (cls: string, text: string): HTMLElement => {
      const node = document.createElement("p");
      node.className = cls;
      node.textContent = text;
      panel.appendChild(node);
      return node;
    };
    const blocked = sim.isDirect && sim.blockedBy.length > 0;
    if (blocked) {
      const names = sim.blockedBy.slice(0, 4).join(", ");
      const suffix =
        sim.blockedBy.length > 4 ? ` +${sim.blockedBy.length - 4}` : "";
      addP(
        "list-sim-blocked",
        `Removing the manifest entry frees nothing today: still required by ${names}${suffix}. If those dependents dropped it, removal would free:`,
      );
    }
    const sizeText =
      freedBytes > 0
        ? ` \u00b7 ${formatByteSize(freedBytes)} on disk${
            sizedCount < sim.freed.length
              ? ` (${sizedCount.toLocaleString()} of ${sim.freed.length.toLocaleString()} measured)`
              : ""
          }`
        : "";
    const rollups = [
      ...(vulns ? [`${vulns} vulnerable`] : []),
      ...(licenses ? [`${licenses} licence issue${licenses === 1 ? "" : "s"}`] : []),
      ...(maint ? [`${maint} maintenance concern${maint === 1 ? "" : "s"}`] : []),
    ];
    const headlineP = addP(
      "list-sim-headline",
      `\u2702 ${blocked ? "Would free" : "Frees"} ${sim.freed.length.toLocaleString()} package${sim.freed.length === 1 ? "" : "s"}${sizeText}${
        rollups.length > 0 ? ` \u00b7 including ${rollups.join(" \u00b7 ")}` : ""
      }`,
    );
    headlineP.insertAdjacentHTML("beforeend", finePrintBtnHtml("impact"));
    // Grouped the same way the expanded view's subsections are: a title with
    // a one-line description beside it, then package tags.
    const nameList = (
      title: string,
      desc: string,
      entries: Array<{ name: string; note?: string }>,
      cap: number,
    ): void => {
      const group = document.createElement("div");
      group.className = "list-sim-group";
      const head = document.createElement("div");
      head.className = "subsection-header";
      const titleEl = document.createElement("span");
      titleEl.className = "subsection-title";
      titleEl.textContent = title;
      const descEl = document.createElement("span");
      descEl.className = "subsection-desc";
      descEl.textContent = desc;
      head.append(titleEl, descEl);
      group.appendChild(head);
      const wrap = document.createElement("div");
      wrap.className = "package-list";
      for (const entry of entries.slice(0, cap)) {
        const chip = document.createElement("span");
        chip.className = "package-tag";
        if (entry.note) {
          const nameEl = document.createElement("span");
          nameEl.textContent = entry.name;
          const noteEl = document.createElement("span");
          noteEl.className = "package-tag-note";
          noteEl.textContent = entry.note;
          chip.append(nameEl, noteEl);
        } else {
          chip.textContent = entry.name;
        }
        wrap.appendChild(chip);
      }
      if (entries.length > cap) {
        const more = document.createElement("span");
        more.className = "package-tag list-sim-more";
        more.textContent = `+${entries.length - cap} more`;
        wrap.appendChild(more);
      }
      group.appendChild(wrap);
      panel.appendChild(group);
    };
    const nameCounts = new Map<string, number>();
    for (const entry of [...sim.freed, ...sim.retained]) {
      nameCounts.set(entry.name, (nameCounts.get(entry.name) ?? 0) + 1);
    }
    const simLabel = (entry: { slug: string; name: string }): string =>
      (nameCounts.get(entry.name) ?? 0) > 1 ? entry.slug : entry.name;
    nameList(
      `Freed (${sim.freed.length})`,
      "Leave node_modules: nothing else needs them",
      sim.freed.map((f) => ({ name: simLabel(f) })),
      30,
    );
    if (sim.retained.length > 0) {
      nameList(
        `Retained (${sim.retained.length})`,
        "Stay installed: another package still depends on them",
        sim.retained.map((r) => ({ name: simLabel(r), note: `kept by ${r.keptBy}` })),
        12,
      );
    }
    if (model.workspaceName && dataset.workspaces.length > 1) {
      const declaring =
        model.workspaceName === "root" && sim.isDirect
          ? dataset.workspaces.filter(
              (w) =>
                w.name !== "root" &&
                (w.directDependencies.includes(simKey) ||
                  w.directDevDependencies.includes(simKey)),
            ).length
          : 0;
      addP(
        "list-sim-note",
        model.workspaceName === "root"
          ? `Computed over the whole project graph.${
              declaring > 1
                ? ` Declared directly by ${declaring} workspaces; freeing requires removing it from each.`
                : ""
            }`
          : `Computed for the ${model.workspaceName} workspace graph.`,
      );
    }
    holder.appendChild(panel);
  }

  // ----- fine-print popover (list view) ---------------------------------
  const listFinePop = document.createElement("div");
  listFinePop.className = "fine-print-pop";
  listFinePop.hidden = true;
  listFinePop.setAttribute("role", "note");
  listFinePop.tabIndex = -1;
  document.body.appendChild(listFinePop);
  let listFineAnchor: HTMLElement | null = null;
  function closeListFinePrint(refocus = false): void {
    if (listFinePop.hidden) return;
    listFinePop.hidden = true;
    listFineAnchor?.setAttribute("aria-expanded", "false");
    if (refocus) listFineAnchor?.focus();
    listFineAnchor = null;
  }
  function openListFinePrint(topic: string, anchor: HTMLElement): void {
    const note = FINE_PRINT[topic];
    if (!note) return;
    if (!listFinePop.hidden && listFineAnchor === anchor) {
      closeListFinePrint(true);
      return;
    }
    listFineAnchor?.setAttribute("aria-expanded", "false");
    listFineAnchor = anchor;
    anchor.setAttribute("aria-expanded", "true");
    listFinePop.textContent = "";
    const strong = document.createElement("strong");
    strong.textContent = note.title;
    const body = document.createElement("p");
    body.textContent = note.body;
    listFinePop.append(strong, body);
    listFinePop.hidden = false;
    const rect = anchor.getBoundingClientRect();
    const popH = listFinePop.offsetHeight;
    const popW = 288;
    let top = rect.bottom + 6;
    if (top + popH > window.innerHeight - 8) top = rect.top - popH - 6;
    listFinePop.style.top = `${Math.max(8, top)}px`;
    listFinePop.style.left = `${Math.max(8, Math.min(rect.left - 140, window.innerWidth - popW - 8))}px`;
    listFinePop.focus({ preventScroll: true });
  }
  document.addEventListener("pointerdown", (event) => {
    if (listFinePop.hidden) return;
    const target = event.target as Node;
    if (listFinePop.contains(target) || listFineAnchor?.contains(target)) return;
    closeListFinePrint();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !listFinePop.hidden) closeListFinePrint(true);
  });
  // A fixed-position note drifts from its anchor on any scroll — close it.
  document.addEventListener("scroll", () => closeListFinePrint(), {
    capture: true,
    passive: true,
  });
  document.addEventListener("click", (event) => {
    const btn = (event.target as HTMLElement).closest<HTMLElement>(
      ".fine-print-btn[data-fine-topic]",
    );
    if (!btn) return;
    event.preventDefault();
    event.stopPropagation();
    openListFinePrint(btn.dataset.fineTopic || "", btn);
  });

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
  // ----- hash router ----------------------------------------------------
  // Discrete UI transitions (view switch, filters, selection, graph mode,
  // workspace) are mirrored into location.hash so browser back/forward
  // walks them. Camera panning/zooming is deliberately NOT recorded.
  function buildRouteHash(): string {
    const params = new URLSearchParams();
    if (currentView === "graph" && graphModes) {
      const r = graphModes.routeState();
      params.set("mode", r.mode);
      if (r.workspace) params.set("ws", r.workspace);
      if (r.selected) params.set("pkg", r.selected);
      if (r.highlights.length > 0) params.set("hl", r.highlights.join(","));
      if (!r.runtime) params.set("rt", "0");
      if (!r.dev) params.set("dev", "0");
      if (!r.sub) params.set("sub", "0");
      if (r.depth !== null) params.set("depth", String(r.depth));
      const query = params.toString();
      return "#/graph" + (query ? `?${query}` : "");
    }
    if (controls.search.value) params.set("q", controls.search.value);
    if (controls.direct.value !== "all") params.set("type", controls.direct.value);
    if (controls.runtime.value !== "all") params.set("scope", controls.runtime.value);
    if (controls.workspace && controls.workspace.value !== "all") {
      params.set("ws", controls.workspace.value);
    }
    const flagParams: Array<[string, HTMLInputElement | null | undefined]> = [
      ["vuln", controls.hasVulns],
      ["maint", controls.maintenanceConcerns],
      ["lic", controls.licenseIssues],
      ["blockers", controls.upgradeBlockers],
      ["repl", controls.hasReplacement],
      ["noimports", controls.noImports],
      ["dups", controls.duplicateVersions],
    ];
    for (const [key, ctrl] of flagParams) if (ctrl?.checked) params.set(key, "1");
    const licenseParams: Array<[string, HTMLInputElement]> = [
      ["lp", controls.licensePermissive],
      ["lw", controls.licenseWeakCopyleft],
      ["ls", controls.licenseStrongCopyleft],
      ["lu", controls.licenseUnknown],
    ];
    for (const [key, ctrl] of licenseParams) if (!ctrl.checked) params.set(key, "0");
    if (routeExpandedKey) params.set("pkg", routeExpandedKey);
    const query = params.toString();
    return "#/list" + (query ? `?${query}` : "");
  }

  function routeSync(pushRoute: boolean): void {
    if (applyingRoute || !routerReady) return;
    const hash = buildRouteHash();
    if (hash === location.hash) return;
    lastSyncedHash = hash;
    const url = location.pathname + location.search + hash;
    try {
      if (pushRoute) history.pushState(null, "", url);
      else history.replaceState(null, "", url);
    } catch {
      // Some file:// contexts refuse pushState — fall back to the hash
      // itself (lastSyncedHash stops the hashchange listener re-applying).
      location.hash = hash.slice(1);
    }
  }

  function applyRouteFromHash(): void {
    // The pre-router base entry has no hash — treat it as the default list
    // route so Back past the first recorded state still resets the UI.
    const hash = location.hash.startsWith("#/") ? location.hash : "#/list";
    applyingRoute = true;
    try {
      const queryIndex = hash.indexOf("?");
      const path = queryIndex < 0 ? hash.slice(2) : hash.slice(2, queryIndex);
      const params = new URLSearchParams(
        queryIndex < 0 ? "" : hash.slice(queryIndex + 1),
      );
      if (path === "graph") {
        setActiveView("graph");
        if (graphModes) {
          const fallback = graphModes.routeState();
          graphModes.applyRoute({
            mode: (params.get("mode") as GraphRoute["mode"]) || fallback.mode,
            workspace: params.get("ws") ?? "",
            selected: params.get("pkg"),
            highlights: (params.get("hl") ?? "").split(",").filter(Boolean),
            runtime: params.get("rt") !== "0",
            dev: params.get("dev") !== "0",
            sub: params.get("sub") !== "0",
            depth: params.has("depth")
              ? Number.parseInt(params.get("depth") ?? "", 10) || null
              : null,
          });
        }
        return;
      }
      setActiveView("list");
      controls.search.value = params.get("q") ?? "";
      controls.direct.value = params.get("type") ?? "all";
      controls.runtime.value = params.get("scope") ?? "all";
      if (controls.workspace) controls.workspace.value = params.get("ws") ?? "all";
      const setChecked = (
        ctrl: HTMLInputElement | null | undefined,
        value: boolean,
      ): void => {
        if (ctrl && !ctrl.disabled) ctrl.checked = value;
      };
      setChecked(controls.hasVulns, params.get("vuln") === "1");
      setChecked(controls.maintenanceConcerns, params.get("maint") === "1");
      setChecked(controls.licenseIssues, params.get("lic") === "1");
      setChecked(controls.upgradeBlockers, params.get("blockers") === "1");
      setChecked(controls.hasReplacement, params.get("repl") === "1");
      setChecked(controls.noImports, params.get("noimports") === "1");
      setChecked(controls.duplicateVersions, params.get("dups") === "1");
      controls.licensePermissive.checked = params.get("lp") !== "0";
      controls.licenseWeakCopyleft.checked = params.get("lw") !== "0";
      controls.licenseStrongCopyleft.checked = params.get("ls") !== "0";
      controls.licenseUnknown.checked = params.get("lu") !== "0";
      const pkg = params.get("pkg");
      routeExpandedKey = pkg;
      // Reconcile expanded cards with the route: anything else closes.
      for (const key of [...openDepKeys]) {
        if (key !== pkg) openDepKeys.delete(key);
      }
      forcedVisibleDepKeys.clear();
      renderList();
      if (pkg && depByKey.has(pkg)) openListFromGraph(pkg);
    } finally {
      applyingRoute = false;
    }
  }

  window.addEventListener("popstate", handleRouteNavigation);
  window.addEventListener("hashchange", handleRouteNavigation);
  function handleRouteNavigation(): void {
    if (location.hash === lastSyncedHash) return;
    lastSyncedHash = location.hash;
    applyRouteFromHash();
  }

  // Initial render
  updateColumnHeaders();
  renderList();
  setActiveView("list");
  // Restore a deep link, then start mirroring state into the hash.
  if (location.hash.startsWith("#/")) {
    lastSyncedHash = location.hash;
    applyRouteFromHash();
  }
  routerReady = true;
}

// Initialize on DOM ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
