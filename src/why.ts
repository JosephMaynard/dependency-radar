import type { AggregatedData } from './types';

function directDependencyIds(data: AggregatedData): string[] {
  return Object.values(data.dependencies || {})
    .filter((dep) => dep.usage.direct)
    .map((dep) => dep.package.id)
    .sort();
}

function childIds(dep: AggregatedData['dependencies'][string]): string[] {
  return Object.values(dep.graph.subDeps || {})
    .flatMap((group) => Object.values(group || {}) as Array<[string, string | null]>)
    .map((entry) => entry[1])
    .filter((resolved): resolved is string => Boolean(resolved));
}

export function findDependencyPaths(
  data: AggregatedData,
  packageName: string,
  options: { limit?: number } = {}
): string[][] {
  const limit = options.limit ?? 10;
  const targetIds = new Set(
    Object.values(data.dependencies || {})
      .filter((dep) => dep.package.name === packageName || dep.package.id === packageName)
      .map((dep) => dep.package.id)
  );
  if (targetIds.size === 0) return [];

  const paths: string[][] = [];
  const queue = directDependencyIds(data).map((id) => [id]);
  while (queue.length > 0 && paths.length < limit) {
    const path = queue.shift()!;
    const currentId = path[path.length - 1];
    if (targetIds.has(currentId)) {
      paths.push(path);
      continue;
    }
    const current = data.dependencies[currentId];
    if (!current) continue;
    for (const child of childIds(current).sort()) {
      if (path.includes(child)) continue;
      queue.push([...path, child]);
    }
  }
  return paths;
}

export function formatWhyOutput(data: AggregatedData, packageName: string): string {
  const paths = findDependencyPaths(data, packageName);
  const matches = Object.values(data.dependencies || {})
    .filter((dep) => dep.package.name === packageName || dep.package.id === packageName)
    .sort((a, b) => a.package.id.localeCompare(b.package.id));
  if (paths.length === 0 && matches.length === 0) return `Package not found or no path identified: ${packageName}`;
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
