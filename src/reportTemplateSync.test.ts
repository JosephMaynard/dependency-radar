import { describe, expect, it } from 'vitest';
import fs from 'fs';
import path from 'path';

// The graph section markup exists twice: in the Vite dev harness
// (report-ui/index.html) and in the generated-report template (src/report.ts).
// The report UI looks elements up by id, so a drifted id silently disables a
// feature in one context. This test pins the two id sets together.

function graphSectionIds(source: string): string[] {
  const start = source.indexOf('id="graph-view"');
  if (start === -1) return [];
  const end = source.indexOf('</section>', start);
  const section = source.slice(start, end === -1 ? undefined : end);
  const ids = new Set<string>();
  for (const match of section.matchAll(/id="([^"]+)"/g)) {
    ids.add(match[1]);
  }
  return [...ids].sort();
}

describe('graph template synchronisation', () => {
  it('keeps the graph section ids identical between the dev harness and the report template', () => {
    const root = path.join(__dirname, '..');
    const devHtml = fs.readFileSync(path.join(root, 'report-ui', 'index.html'), 'utf8');
    const reportTs = fs.readFileSync(path.join(root, 'src', 'report.ts'), 'utf8');

    const devIds = graphSectionIds(devHtml);
    const reportIds = graphSectionIds(reportTs);

    expect(devIds.length).toBeGreaterThan(5);
    expect(reportIds).toEqual(devIds);
  });
});
