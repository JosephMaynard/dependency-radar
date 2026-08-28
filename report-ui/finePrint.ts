// Shared fine-print copy for measured numbers and static-analysis leads.
// Rendered as (i) popovers in both the graph dossier and the list view, and
// collected under "About these numbers" in the graph Key panel.
export const FINE_PRINT: Record<string, { title: string; body: string }> = {
  size: {
    title: "Measured install size",
    body:
      "Measured on disk as installed (uncompressed). Not download size and not bundle impact: bundlers tree-shake and compress. With pnpm, files are hard-linked to a shared store, so deleting reclaims less physical disk. Each installed version is measured once.",
  },
  imports: {
    title: "Import evidence",
    body:
      "From static scanning of this project's source. CLI binaries, config-file references, and framework conventions are invisible to it, so treat “no imports found” as a lead to check, not a verdict.",
  },
  slide: {
    title: "What the scorecard shows",
    body:
      "The same numbers as the chips at the top of the report, counted the same way. Install size is the measured on-disk total, not download or bundle size. When a check did not run its tile says Not checked, so a zero always means the scan looked and found nothing.",
  },
  impact: {
    title: "Removal impact",
    body:
      "“Removing it frees” counts packages nothing else keeps installed, computed over the full workspace graph. Display filters never change it. A direct dependency that other packages still pull in frees nothing until those dependents drop it.",
  },
};
