// Structural view of the report fields this module actually reads, so both
// the CLI's AggregatedData and the report UI's mirrored type satisfy it
// without casts.
export interface WorkspaceFilterReport {
  workspaces: {
    enabled: boolean;
    workspacePackages?: Array<{ name?: string }>;
  };
  dependencies?: Record<
    string,
    { usage: { origins: { workspaces?: string[] } } }
  >;
}

export function buildWorkspaceFilterOptions(
  report: WorkspaceFilterReport
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
