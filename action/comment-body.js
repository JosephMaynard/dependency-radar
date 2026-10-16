'use strict';

// Builds the markdown for the PR comment and the job summary. Pure functions
// only, so it can be dry-run locally with `node action/publish.js` and
// DR_DRY_RUN=true.

const MARKER = '<!-- dependency-radar-scorecard -->';

// One sticky comment per scanned project, so a monorepo can run the action
// once per package without the comments overwriting each other.
function markerFor(project) {
  const normalized = String(project || '.').replace(/\\/g, '/').replace(/^\.\/+/, '').replace(/\/+$/, '');
  if (!normalized || normalized === '.') return MARKER;
  return '<!-- dependency-radar-scorecard project=' + normalized.replace(/-->/g, '') + ' -->';
}

// Strip ANSI colour codes from captured CLI output.
function plain(text) {
  // eslint-disable-next-line no-control-regex
  return String(text || '').replace(/\u001b\[[0-9;]*m/g, '').replace(/\r/g, '');
}

// Pull the "Policy violations detected:" block out of the CLI log. The CLI
// prints the heading, then "- rule message" lines with "  - detail" lines
// under them.
function extractPolicyViolations(logText) {
  const lines = plain(logText).split('\n');
  const start = lines.findIndex((line) => /Policy violations detected:/.test(line));
  if (start < 0) return [];
  const out = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^\s*- /.test(line)) out.push(line.replace(/\s+$/, ''));
    else if (line.trim() === '') { if (out.length) break; }
    else break;
  }
  return out;
}

function extractIncompleteEvidence(logText) {
  const lines = plain(logText).split('\n');
  const start = lines.findIndex((line) => /Scan evidence is incomplete:/.test(line));
  if (start < 0) return [];
  const out = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^\s*- /.test(lines[i])) out.push(lines[i].trim().replace(/^- /, ''));
    else break;
  }
  return out;
}

// Same wording as the Scorecard tiles in src/slide/slideSvg.ts.
const TILES = [
  { key: 'vulnerabilities', label: 'Vulnerabilities', zero: 'none reported by audit' },
  { key: 'maintenance', label: 'Maintenance concerns', zero: 'all packages look active' },
  { key: 'licenses', label: 'Licence issues', zero: 'all licences look permissive' },
  { key: 'blockers', label: 'Upgrade blockers', zero: 'nothing pins an upgrade' },
  { key: 'duplicates', label: 'Duplicate versions', zero: 'one installed copy each' },
];

function escapeHtml(text) {
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function cell(text) {
  return String(text).replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

function metricText(metric, zero) {
  if (!metric || metric.count < 0) return 'Not checked in this scan';
  if (metric.count === 0) return '0 · ' + zero;
  return metric.count + (metric.detail ? ' · ' + metric.detail : '');
}

function summaryTable(summary) {
  const rows = [
    '| Check | Result |',
    '|---|---|',
    '| Dependencies | ' + cell(summary.dependencyCount + ' · ' + summary.directCount + ' direct · ' + summary.transitiveCount + ' transitive') + ' |',
  ];
  if (summary.installSize) {
    rows.push('| Install size | ' + cell(summary.installSize + ' measured across ' + summary.measuredPackageCount + ' packages') + ' |');
  }
  if (summary.metrics) {
    for (const tile of TILES) {
      rows.push('| ' + tile.label + ' | ' + cell(metricText(summary.metrics[tile.key], tile.zero)) + ' |');
    }
  }
  return rows.join('\n');
}

function policyLine(state) {
  const rules = state.failOn ? state.failOn.split(',').map((r) => '`' + r.trim() + '`').filter((r) => r !== '``').join(', ') : '';
  if (state.exitCode === 0) {
    return rules ? '**Policy:** passed (' + rules + ')' : '**Policy:** no `fail-on` rules set';
  }
  if (state.exitCode === 1) return '**Policy:** failed (' + (rules || 'see log') + ')';
  return '**Policy:** could not be checked, the scan exited with code ' + state.exitCode + ' (incomplete evidence or an error, see the job log)';
}

// Code blocks inside <details> need the fence to be longer than any run of
// backticks in the content.
function fenced(text) {
  const longest = (String(text).match(/`+/g) || []).reduce((max, run) => Math.max(max, run.length), 0);
  const fence = '`'.repeat(Math.max(3, longest + 1));
  return fence + 'text\n' + text + '\n' + fence;
}

function truncate(text, max) {
  if (text.length <= max) return text;
  return text.slice(0, max) + '\n... (truncated, the full output is in the job log)';
}

/**
 * state = {
 *   project, summary, imageUrl, runUrl, headSha, exitCode, failOn,
 *   scanLog, compareText, compareExitCode, baseline, notes: string[],
 *   artifactName, forSummary
 * }
 */
function buildBody(state) {
  const parts = [];
  if (!state.forSummary) parts.push(markerFor(state.project));
  const summary = state.summary || {};
  const projectLabel = state.project && state.project !== '.' ? ' · `' + state.project + '`' : '';
  parts.push('### Dependency Radar' + projectLabel);
  parts.push('');

  if (summary.missing) {
    parts.push('No report was produced. Either the project has no installed dependencies (run `npm ci` or your package manager\'s install before this action) or the scan failed; the job log has the details.');
    parts.push('');
    const tail = plain(state.scanLog || '').trim().split('\n').slice(-40).join('\n');
    if (tail) {
      parts.push('<details><summary>Scan output (last 40 lines)</summary>');
      parts.push('');
      parts.push(fenced(tail));
      parts.push('');
      parts.push('</details>');
      parts.push('');
    }
  } else {
    if (state.imageUrl) {
      const alt = 'Dependency Radar scorecard' + (summary.projectName ? ' for ' + summary.projectName : '');
      const img = '<img src="' + escapeHtml(state.imageUrl) + '" alt="' + escapeHtml(alt) + '">';
      parts.push(state.runUrl ? '<a href="' + escapeHtml(state.runUrl) + '">' + img + '</a>' : img);
      parts.push('');
    }
    if (summary.treeIncomplete) {
      parts.push('> Partial scan. The dependency tree is incomplete, so counts are lower bounds.');
      parts.push('');
    }
    if (state.imageUrl) {
      parts.push('<details><summary>Scorecard as text</summary>');
      parts.push('');
      parts.push(summaryTable(summary));
      parts.push('');
      parts.push('</details>');
    } else {
      parts.push(summaryTable(summary));
    }
    parts.push('');
  }

  parts.push(policyLine(state));
  parts.push('');

  const violations = extractPolicyViolations(state.scanLog || '');
  const compareViolations = extractPolicyViolations(state.compareText || '');
  const allViolations = violations.concat(compareViolations.filter((line) => violations.indexOf(line) < 0));
  if (allViolations.length) {
    parts.push('<details' + (state.exitCode === 1 ? ' open' : '') + '><summary>Policy violations</summary>');
    parts.push('');
    parts.push(fenced(truncate(allViolations.join('\n'), 20000)));
    parts.push('');
    parts.push('</details>');
    parts.push('');
  }

  const incomplete = extractIncompleteEvidence(state.scanLog || '');
  if (incomplete.length) {
    parts.push('<details><summary>Incomplete evidence</summary>');
    parts.push('');
    for (const reason of incomplete) parts.push('- ' + reason);
    parts.push('');
    parts.push('</details>');
    parts.push('');
  }

  // The compare log ends with the same policy block shown above, so only
  // the change list goes in here.
  const changes = plain(state.compareText || '').split(/\n.*Policy violations detected:/)[0].trim();
  if (changes) {
    parts.push('<details><summary>Changes compared with <code>' + escapeHtml(state.baseline || 'baseline') + '</code></summary>');
    parts.push('');
    parts.push(fenced(truncate(changes, 30000)));
    parts.push('');
    parts.push('</details>');
    parts.push('');
  }

  for (const note of state.notes || []) {
    parts.push('> ' + note);
    parts.push('');
  }

  const footer = [];
  if (summary.toolVersion) footer.push('Dependency Radar ' + summary.toolVersion);
  if (state.headSha) footer.push('scanned ' + state.headSha.slice(0, 7));
  if (state.runUrl) {
    footer.push(state.artifactName
      ? '[full HTML report](' + state.runUrl + ') in the `' + state.artifactName + '` artifact'
      : '[workflow run](' + state.runUrl + ')');
  }
  if (footer.length) parts.push('<sub>' + footer.join(' · ') + '</sub>');

  return parts.join('\n').replace(/\n{3,}/g, '\n\n').trim() + '\n';
}

module.exports = {
  MARKER,
  markerFor,
  plain,
  extractPolicyViolations,
  extractIncompleteEvidence,
  summaryTable,
  buildBody,
};
