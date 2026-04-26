"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.findDependencyPaths = findDependencyPaths;
exports.formatWhyOutput = formatWhyOutput;
function directDependencyIds(data) {
    return Object.values(data.dependencies || {})
        .filter((dep) => dep.usage.direct)
        .map((dep) => dep.package.id)
        .sort();
}
function childIds(dep) {
    return Object.values(dep.graph.subDeps || {})
        .flatMap((group) => Object.values(group || {}))
        .map((entry) => entry[1])
        .filter((resolved) => Boolean(resolved));
}
function findDependencyPaths(data, packageName, options = {}) {
    var _a;
    const limit = (_a = options.limit) !== null && _a !== void 0 ? _a : 10;
    const targetIds = new Set(Object.values(data.dependencies || {})
        .filter((dep) => dep.package.name === packageName || dep.package.id === packageName)
        .map((dep) => dep.package.id));
    if (targetIds.size === 0)
        return [];
    const paths = [];
    const queue = directDependencyIds(data).map((id) => [id]);
    while (queue.length > 0 && paths.length < limit) {
        const path = queue.shift();
        const currentId = path[path.length - 1];
        if (targetIds.has(currentId)) {
            paths.push(path);
            continue;
        }
        const current = data.dependencies[currentId];
        if (!current)
            continue;
        for (const child of childIds(current).sort()) {
            if (path.includes(child))
                continue;
            queue.push([...path, child]);
        }
    }
    return paths;
}
function formatWhyOutput(data, packageName) {
    const paths = findDependencyPaths(data, packageName);
    const matches = Object.values(data.dependencies || {})
        .filter((dep) => dep.package.name === packageName || dep.package.id === packageName)
        .sort((a, b) => a.package.id.localeCompare(b.package.id));
    if (paths.length === 0 && matches.length === 0)
        return `Package not found or no path identified: ${packageName}`;
    const lines = [`Dependency paths for ${packageName}`, '-'.repeat(Math.max(24, packageName.length + 21)), ''];
    if (paths.length === 0) {
        for (const dep of matches) {
            lines.push(dep.package.id);
            if (dep.usage.origins.topRootPackages.length > 0) {
                lines.push(`  roots: ${dep.usage.origins.topRootPackages.map((root) => `${root.name}@${root.version}`).join(', ')}`);
            }
            if (dep.usage.origins.topParentPackages.length > 0) {
                lines.push(`  parents: ${dep.usage.origins.topParentPackages.join(', ')}`);
            }
        }
        return lines.join('\n');
    }
    for (const path of paths) {
        lines.push(path.join(' -> '));
    }
    return lines.join('\n');
}
