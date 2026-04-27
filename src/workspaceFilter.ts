import type { AggregatedData } from './types';

export function buildWorkspaceFilterOptions(
  report: Pick<AggregatedData, 'workspaces' | 'dependencies'>
): string[] {
  if (!report.workspaces.enabled) return [];

  const names = new Set<string>();
  (report.workspaces.workspacePackages || []).forEach((workspace) => {
    if (workspace.name) names.add(workspace.name);
  });
  Object.values(report.dependencies || {}).forEach((dep) => {
    (dep.usage.origins.workspaces || []).forEach((workspaceName) => {
      if (workspaceName) names.add(workspaceName);
    });
  });

  return Array.from(names).sort((a, b) => {
    if (a === 'root') return -1;
    if (b === 'root') return 1;
    return a.localeCompare(b);
  });
}
