import { describe, expect, it } from 'vitest';
import fs from 'fs';
import path from 'path';

// The graph section markup exists twice: in the Vite dev harness
// (report-ui/index.html) and in the generated-report template (src/report.ts).
// The report UI looks elements up by id, so a drifted id silently disables a
// feature in one context. This test pins the two id sets together.

function graphSectionIds(source: string): string[] {
  const start = source.indexOf('id="graph-view"');
  expect(start, 'graph-view section missing').toBeGreaterThanOrEqual(0);
  const end = source.indexOf('</section>', start);
  expect(end, 'graph-view section is unterminated').toBeGreaterThan(start);
  const section = source.slice(start, end);
  const ids: string[] = [];
  for (const match of section.matchAll(/id="([^"]+)"/g)) {
    ids.push(match[1]);
  }
  // Duplicate DOM ids within one template are their own bug; a Set here
  // would silently mask them.
  expect(new Set(ids).size, 'duplicate ids within the graph section').toBe(ids.length);
  return ids.sort();
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

  it('keeps the scorecard section ids identical between the dev harness and the report template', () => {
    const root = path.join(__dirname, '..');
    const devHtml = fs.readFileSync(path.join(root, 'report-ui', 'index.html'), 'utf8');
    const reportTs = fs.readFileSync(path.join(root, 'src', 'report.ts'), 'utf8');

    const devIds = sectionIds(devHtml, 'scorecard-view');
    const reportIds = sectionIds(reportTs, 'scorecard-view');

    expect(devIds.length).toBeGreaterThan(5);
    expect(reportIds).toEqual(devIds);
  });
});

function sectionIds(source: string, sectionId: string): string[] {
  const start = source.indexOf(`id="${sectionId}"`);
  expect(start, `${sectionId} section missing`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf('</section>', start);
  expect(end, `${sectionId} section is unterminated`).toBeGreaterThan(start);
  const section = source.slice(start, end);
  const ids: string[] = [];
  for (const match of section.matchAll(/id="([^"]+)"/g)) {
    ids.push(match[1]);
  }
  expect(new Set(ids).size, `duplicate ids within the ${sectionId} section`).toBe(ids.length);
  return ids.sort();
}
