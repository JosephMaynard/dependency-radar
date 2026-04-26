"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.compareReports = compareReports;
exports.formatCompareOutput = formatCompareOutput;
function byName(deps) {
    const map = new Map();
    for (const dep of Object.values(deps || {})) {
        if (!map.has(dep.package.name))
            map.set(dep.package.name, []);
        map.get(dep.package.name).push(dep);
    }
    return map;
}
function compareReports(previous, current) {
    const previousIds = new Set(Object.keys(previous.dependencies || {}));
    const currentIds = new Set(Object.keys(current.dependencies || {}));
    const added = Array.from(currentIds).filter((id) => !previousIds.has(id)).sort();
    const removed = Array.from(previousIds).filter((id) => !currentIds.has(id)).sort();
    const previousByName = byName(previous.dependencies || {});
    const currentByName = byName(current.dependencies || {});
    const changedVersions = [];
    for (const [name, previousDeps] of previousByName.entries()) {
        const currentDeps = currentByName.get(name);
        if (!currentDeps || currentDeps.length !== 1 || previousDeps.length !== 1)
            continue;
        const prev = previousDeps[0];
        const next = currentDeps[0];
        if (prev.package.version !== next.package.version) {
            changedVersions.push({ name, from: prev.package.version, to: next.package.version });
        }
    }
    changedVersions.sort((a, b) => a.name.localeCompare(b.name));
    const previousFindingIds = new Set((previous.findings || []).map((finding) => finding.id));
    const currentFindingIds = new Set((current.findings || []).map((finding) => finding.id));
    return {
        added,
        removed,
        changedVersions,
        newFindings: (current.findings || []).filter((finding) => !previousFindingIds.has(finding.id)),
        resolvedFindings: (previous.findings || []).filter((finding) => !currentFindingIds.has(finding.id))
    };
}
function section(title, lines, empty) {
    return [
        title,
        '-'.repeat(title.length),
        ...(lines.length > 0 ? lines : [empty]),
        ''
    ];
}
function formatCompareOutput(result) {
    const lines = ['Dependency Radar comparison', '===========================', ''];
    lines.push(...section('Added dependencies', result.added.map((id) => `+ ${id}`), 'none'));
    lines.push(...section('Removed dependencies', result.removed.map((id) => `- ${id}`), 'none'));
    lines.push(...section('Changed versions', result.changedVersions.map((entry) => `${entry.name}: ${entry.from} -> ${entry.to}`), 'none'));
    lines.push(...section('New findings', result.newFindings.map((finding) => `${finding.severity.toUpperCase()} ${finding.packageId}: ${finding.title}`), 'none'));
    lines.push(...section('Resolved findings', result.resolvedFindings.map((finding) => `${finding.packageId}: ${finding.title}`), 'none'));
    return lines.join('\n').trimEnd();
}
