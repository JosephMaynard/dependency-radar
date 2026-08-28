"use strict";
/**
 * Distills a scan's aggregated data into the small set of figures the slide
 * dashboard shows. Pure and dependency-free so the same module serves the
 * report UI (bundled by Vite) and the CLI (compiled by tsc).
 *
 * Counting semantics deliberately mirror the report header chips in
 * report-ui/main.ts (populateHeaderStats and its predicates), so the slide
 * never disagrees with the report it came from: vulnerable packages count
 * records with any reported vulnerability, advisories are distinct ids
 * (the `via` expansion lands one advisory on several records), maintenance
 * concerns are deprecated/archived/unmaintained/stale/slowing, licence
 * issues are any non-green licence risk, and upgrade blockers include Node
 * target blockers.
 *
 * Input types are narrow structural subsets of the aggregated data rather
 * than imports of the full AggregatedData type, so both the src and
 * report-ui mirrors of that type satisfy them.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SIZE_BLOCK_LIMIT = void 0;
exports.buildSlideModel = buildSlideModel;
const MAINTENANCE_CONCERNS = new Set([
    "deprecated",
    "archived",
    "unmaintained",
    "stale",
    "slowing",
]);
const NOT_CHECKED = -1;
function vulnerabilityTotal(dep) {
    var _a;
    const s = (_a = dep.security) === null || _a === void 0 ? void 0 : _a.summary;
    if (!s)
        return 0;
    return ((s.critical || 0) + (s.high || 0) + (s.moderate || 0) + (s.low || 0));
}
function plural(count, word) {
    return count + " " + word + (count === 1 ? "" : "s");
}
/** How many of the largest packages the hero treemap shows by name. */
exports.SIZE_BLOCK_LIMIT = 8;
function buildSlideModel(data) {
    var _a, _b, _c, _d, _e, _f, _g, _h;
    const deps = Object.values(data.dependencies);
    const collectors = ((_a = data.scanStatus) === null || _a === void 0 ? void 0 : _a.collectors) || {};
    const collectorRan = (name) => {
        const status = collectors[name];
        // Reports predating scanStatus carry no collector map and count as
        // checked. "partial" does not: the header chips grey out on anything
        // other than "available", and a slide must not present a count from an
        // audit that covered only part of the tree as definitive.
        return status === undefined || status === "available";
    };
    // Vulnerabilities: affected packages + distinct advisory ids.
    let vulnerablePackages = 0;
    let highestSeverity = "none";
    const severityRank = {
        none: 0,
        low: 1,
        moderate: 2,
        high: 3,
        critical: 4,
    };
    const advisoryIds = new Set();
    for (const dep of deps) {
        if (vulnerabilityTotal(dep) > 0) {
            vulnerablePackages += 1;
            const highest = ((_c = (_b = dep.security) === null || _b === void 0 ? void 0 : _b.summary) === null || _c === void 0 ? void 0 : _c.highest) || "none";
            if ((severityRank[highest] || 0) > (severityRank[highestSeverity] || 0)) {
                highestSeverity = highest;
            }
        }
        for (const advisory of ((_d = dep.security) === null || _d === void 0 ? void 0 : _d.advisories) || []) {
            if ((advisory === null || advisory === void 0 ? void 0 : advisory.id) !== undefined)
                advisoryIds.add(String(advisory.id));
        }
    }
    // Headline matches the header chip exactly: distinct advisory ids, with
    // the affected-package count as the fallback for audit formats that carry
    // severity totals but no advisory detail.
    const advisoryCount = advisoryIds.size;
    const advisoryDetailMissing = advisoryCount === 0 && vulnerablePackages > 0;
    const vulnerabilities = !collectorRan("audit")
        ? { count: NOT_CHECKED, detail: "", tone: "gray" }
        : {
            count: advisoryDetailMissing ? vulnerablePackages : advisoryCount,
            detail: vulnerablePackages === 0
                ? ""
                : advisoryDetailMissing
                    ? "worst " + highestSeverity
                    : "in " +
                        plural(vulnerablePackages, "package") +
                        " · worst " +
                        highestSeverity,
            tone: vulnerablePackages === 0
                ? "green"
                : highestSeverity === "critical" || highestSeverity === "high"
                    ? "red"
                    : "amber",
        };
    // Maintenance concerns, with a breakdown of the two commonest statuses so
    // the tile always says what kind of concern it is counting.
    let maintenanceCount = 0;
    let deprecatedOrArchived = 0;
    const statusCounts = new Map();
    for (const dep of deps) {
        const status = (_e = dep.maintenance) === null || _e === void 0 ? void 0 : _e.status;
        if (status && MAINTENANCE_CONCERNS.has(status)) {
            maintenanceCount += 1;
            statusCounts.set(status, (statusCounts.get(status) || 0) + 1);
            if (status === "deprecated" || status === "archived") {
                deprecatedOrArchived += 1;
            }
        }
    }
    const statusBreakdown = [...statusCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 2)
        .map((entry) => entry[1] + " " + entry[0])
        .join(" · ");
    // Mirrors the chips' maintenanceDataSeen: without a single attempted
    // lookup there is no basis for a green zero.
    const maintenanceDataSeen = deps.some((dep) => { var _a; return (_a = dep.maintenance) === null || _a === void 0 ? void 0 : _a.attempted; });
    const maintenance = !collectorRan("maintenance") || !maintenanceDataSeen
        ? { count: NOT_CHECKED, detail: "", tone: "gray" }
        : {
            count: maintenanceCount,
            detail: deprecatedOrArchived > 0
                ? deprecatedOrArchived + " deprecated or archived"
                : statusBreakdown,
            tone: maintenanceCount === 0
                ? "green"
                : deprecatedOrArchived > 0
                    ? "red"
                    : "amber",
        };
    // Licence issues (always collected locally from manifests).
    let licenseIssues = 0;
    let licenseHighRisk = 0;
    for (const dep of deps) {
        if (dep.compliance.licenseRisk !== "green") {
            licenseIssues += 1;
            if (dep.compliance.licenseRisk === "red")
                licenseHighRisk += 1;
        }
    }
    const licenses = {
        count: licenseIssues,
        detail: licenseIssues === 0
            ? ""
            : licenseHighRisk > 0
                ? licenseHighRisk + " high risk"
                : "to review · none high risk",
        tone: licenseIssues === 0 ? "green" : licenseHighRisk > 0 ? "red" : "amber",
    };
    // Upgrade blockers.
    let blockerCount = 0;
    let nodeBlockers = 0;
    for (const dep of deps) {
        const blocksNode = Boolean(dep.upgrade.blocksNodeMajor);
        if (blocksNode || (((_f = dep.upgrade.blockers) === null || _f === void 0 ? void 0 : _f.length) || 0) > 0) {
            blockerCount += 1;
            if (blocksNode)
                nodeBlockers += 1;
        }
    }
    const blockers = {
        count: blockerCount,
        detail: nodeBlockers > 0 ? nodeBlockers + " block the Node target" : "",
        tone: blockerCount === 0 ? "green" : "amber",
    };
    // Duplicate installed versions.
    const versionsByName = new Map();
    for (const dep of deps) {
        versionsByName.set(dep.package.name, (versionsByName.get(dep.package.name) || 0) + 1);
    }
    let duplicateNames = 0;
    let extraInstalls = 0;
    for (const versions of versionsByName.values()) {
        if (versions > 1) {
            duplicateNames += 1;
            extraInstalls += versions - 1;
        }
    }
    const duplicates = {
        count: duplicateNames,
        detail: duplicateNames > 0 ? plural(extraInstalls, "extra install") : "",
        tone: duplicateNames === 0 ? "green" : "amber",
    };
    // Measured install size. Records are keyed name@version and each carries
    // one measured path, so the sum measures each installed version once. In
    // stores that keep several physical copies of the same version (isolated
    // workspace installs, peer variants) the true on-disk figure can be
    // higher; the fine print states the same rule the report's size note uses.
    let totalInstallBytes = 0;
    let anyMeasured = false;
    const measured = [];
    for (const dep of deps) {
        const bytes = (_g = dep.package.installSize) === null || _g === void 0 ? void 0 : _g.totalBytes;
        if (typeof bytes === "number") {
            anyMeasured = true;
            totalInstallBytes += bytes;
            measured.push({ name: dep.package.name, bytes });
        }
    }
    measured.sort((a, b) => b.bytes - a.bytes);
    // Zero-byte entries would produce zero-area treemap rects (and NaN
    // geometry when one ends a layout row), so they stay in the total but
    // never become named blocks.
    const blocks = measured
        .filter((entry) => entry.bytes > 0)
        .slice(0, exports.SIZE_BLOCK_LIMIT);
    const sizeBlocks = blocks.map((entry) => ({
        name: entry.name,
        bytes: entry.bytes,
        share: totalInstallBytes > 0 ? entry.bytes / totalInstallBytes : 0,
    }));
    const sizeOtherBytes = totalInstallBytes - blocks.reduce((sum, entry) => sum + entry.bytes, 0);
    // The dependency tree is what every count is built from; partial is
    // as disqualifying as absent for "these are the totals".
    const treeStatus = collectors["dependencyTree"];
    const treeIncomplete = treeStatus !== undefined && treeStatus !== "available";
    return {
        projectName: data.project.name ||
            (
            // Both separators: a Windows projectDir must not leak the full local
            // path into a shareable artifact.
            (_h = data.project.projectDir) === null || _h === void 0 ? void 0 : _h.split(/[\\/]/).filter(Boolean).pop()) ||
            "project",
        treeIncomplete,
        generatedAt: data.generatedAt || "",
        toolVersion: data.dependencyRadarVersion || "",
        dependencyCount: data.summary.dependencyCount,
        directCount: data.summary.directCount,
        transitiveCount: data.summary.transitiveCount,
        totalInstallBytes: anyMeasured ? totalInstallBytes : NOT_CHECKED,
        measuredPackageCount: measured.length,
        sizeBlocks,
        sizeOtherBytes,
        vulnerabilities,
        maintenance,
        licenses,
        blockers,
        duplicates,
    };
}
