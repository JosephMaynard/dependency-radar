'use strict';

// Publishes the scan result: stores the Scorecard image on the assets
// branch, creates or updates the sticky PR comment, and writes the job
// summary. Every GitHub call is best effort. A failed upload or comment
// becomes a warning, never a failed job; only the policy result (handled by
// the final step in action.yml) decides pass or fail.
//
// Set DR_DRY_RUN=true to print the comment instead of calling GitHub.

const fs = require('fs');
const path = require('path');
const gh = require('./lib/github');
const { buildBody, markerFor } = require('./comment-body');

const { env, bool, notice, warning, setOutput } = gh;

const dryRun = bool('DR_DRY_RUN', false);
const project = env('DR_PROJECT', '.');
const assetsBranch = env('DR_ASSETS_BRANCH', 'dependency-radar-assets');
const wantComment = bool('DR_COMMENT', true);
const repository = env('GITHUB_REPOSITORY', '');
const [owner, repo] = repository.split('/');
const serverUrl = env('GITHUB_SERVER_URL', 'https://github.com').replace(/\/+$/, '');
const apiUrl = env('GITHUB_API_URL', 'https://api.github.com');
const eventName = env('GITHUB_EVENT_NAME', '');
const runId = env('GITHUB_RUN_ID', '');
const runUrl = repository && runId ? serverUrl + '/' + repository + '/actions/runs/' + runId : '';

function readText(file) {
  if (!file || !fs.existsSync(file)) return '';
  return fs.readFileSync(file, 'utf8');
}

function readSummary() {
  const file = env('DR_SUMMARY_PATH', '');
  if (!file || !fs.existsSync(file)) return { missing: true };
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    return { missing: true };
  }
}

function projectSlug() {
  const cleaned = String(project).replace(/\\/g, '/').replace(/^\.\/+/, '').replace(/\/+$/, '');
  if (!cleaned || cleaned === '.') return 'root';
  return cleaned.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'root';
}

function refPath(branch) {
  return branch.split('/').map(encodeURIComponent).join('/');
}

const ASSETS_README = [
  '# Dependency Radar scorecards',
  '',
  'The Dependency Radar GitHub Action writes this branch. It holds the Scorecard',
  'images shown in pull request comments, one folder per pull request.',
  '',
  'Nothing here is part of the project. Deleting the branch is safe; old',
  'comments lose their image and the next run starts a fresh branch.',
  '',
].join('\n');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Commit one file to the assets branch through the Git Data API and return
// the new commit SHA. The previous image for the same PR and project is
// removed in the same commit so the branch tip stays small. Retries when
// another run moved the branch in between.
async function uploadImage(request, file, repoPath, pruneDir, message) {
  const content = fs.readFileSync(file).toString('base64');
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    let parent = null;
    let baseTree = null;
    let existing = [];
    try {
      const ref = await request('GET', 'repos/' + owner + '/' + repo + '/git/ref/heads/' + refPath(assetsBranch));
      parent = ref.object.sha;
      const commit = await request('GET', 'repos/' + owner + '/' + repo + '/git/commits/' + parent);
      baseTree = commit.tree.sha;
      const tree = await request('GET', 'repos/' + owner + '/' + repo + '/git/trees/' + baseTree + '?recursive=1');
      existing = (tree.tree || []).filter((entry) => entry.type === 'blob').map((entry) => entry.path);
    } catch (err) {
      if (!(err instanceof gh.GitHubError) || err.status !== 404) throw err;
    }

    const blob = await request('POST', 'repos/' + owner + '/' + repo + '/git/blobs', { content, encoding: 'base64' });
    const entries = [{ path: repoPath, mode: '100644', type: 'blob', sha: blob.sha }];
    for (const old of existing) {
      if (old.indexOf(pruneDir) === 0 && old !== repoPath) {
        entries.push({ path: old, mode: '100644', type: 'blob', sha: null });
      }
    }
    if (existing.indexOf('README.md') < 0) {
      const readme = await request('POST', 'repos/' + owner + '/' + repo + '/git/blobs', {
        content: Buffer.from(ASSETS_README).toString('base64'),
        encoding: 'base64',
      });
      entries.push({ path: 'README.md', mode: '100644', type: 'blob', sha: readme.sha });
    }
    const treeBody = { tree: entries };
    if (baseTree) treeBody.base_tree = baseTree;
    const tree = await request('POST', 'repos/' + owner + '/' + repo + '/git/trees', treeBody);
    const commit = await request('POST', 'repos/' + owner + '/' + repo + '/git/commits', {
      message,
      tree: tree.sha,
      parents: parent ? [parent] : [],
    });

    try {
      if (parent) {
        await request('PATCH', 'repos/' + owner + '/' + repo + '/git/refs/heads/' + refPath(assetsBranch), {
          sha: commit.sha,
          force: false,
        });
      } else {
        await request('POST', 'repos/' + owner + '/' + repo + '/git/refs', {
          ref: 'refs/heads/' + assetsBranch,
          sha: commit.sha,
        });
      }
      return commit.sha;
    } catch (err) {
      // 422: not a fast-forward, or the branch was created by a parallel run.
      if (err instanceof gh.GitHubError && (err.status === 422 || err.status === 409) && attempt < 4) {
        await sleep(500 * attempt);
        continue;
      }
      throw err;
    }
  }
  throw new Error('gave up after repeated conflicts on ' + assetsBranch);
}

// raw.githubusercontent.com works for public repos and survives camo and
// email. Private repos and GHES need the github.com/raw form, which uses the
// viewer's own session. Both point at a commit SHA, so caches never serve a
// stale image.
function imageUrlFor(commitSha, repoPath, isPrivate) {
  const encoded = repoPath.split('/').map(encodeURIComponent).join('/');
  if (!isPrivate && serverUrl === 'https://github.com') {
    return 'https://raw.githubusercontent.com/' + owner + '/' + repo + '/' + commitSha + '/' + encoded;
  }
  return serverUrl + '/' + owner + '/' + repo + '/raw/' + commitSha + '/' + encoded;
}

async function upsertComment(request, number, body) {
  const marker = markerFor(project);
  let found = null;
  for (let page = 1; page <= 30 && !found; page += 1) {
    const comments = await request('GET', 'repos/' + owner + '/' + repo + '/issues/' + number + '/comments?per_page=100&page=' + page);
    for (const comment of comments || []) {
      // First line must be the marker exactly, so a human quoting the bot is
      // never overwritten.
      if (String(comment.body || '').split('\n')[0].trim() === marker) {
        found = comment;
        break;
      }
    }
    if (!comments || comments.length < 100) break;
  }
  if (found) {
    const updated = await request('PATCH', 'repos/' + owner + '/' + repo + '/issues/comments/' + found.id, { body });
    return updated.html_url;
  }
  const created = await request('POST', 'repos/' + owner + '/' + repo + '/issues/' + number + '/comments', { body });
  return created.html_url;
}

const GITHUB_COMMENT_LIMIT = 65000;

async function main() {
  const event = gh.readEvent();
  const pr = event.pull_request || null;
  const headSha = (pr && pr.head && pr.head.sha) || env('GITHUB_SHA', '');
  const isPrivate = Boolean(event.repository && (event.repository.private || event.repository.visibility === 'private' || event.repository.visibility === 'internal'));
  const headRepo = pr && pr.head && pr.head.repo ? pr.head.repo.full_name : '';
  const fromFork = Boolean(pr) && headRepo !== repository;
  // On pull_request, fork PRs only ever get a read-only token.
  const readOnly = fromFork && eventName === 'pull_request';

  const summary = readSummary();
  const notes = [];
  const pngPath = env('DR_PNG_PATH', '');
  const svgPath = env('DR_SVG_PATH', '');
  const image = pngPath && fs.existsSync(pngPath) ? pngPath : svgPath && fs.existsSync(svgPath) ? svgPath : '';

  const token = env('DR_TOKEN', '');
  const request = gh.createClient(token, apiUrl);
  const canPublish = Boolean(pr) && wantComment && !readOnly && Boolean(token) && Boolean(owner && repo);

  if (readOnly) {
    const message =
      'This pull request comes from a fork. GitHub gives fork workflows a read-only token, ' +
      'so the action cannot post a comment or store the image. The scorecard is in this job summary and the run artifacts.';
    notice(message);
    notes.push(message);
  }

  let imageUrl = '';
  if (canPublish && image && !summary.missing) {
    const ext = path.extname(image).toLowerCase();
    const pruneDir = 'pr-' + pr.number + '/' + projectSlug() + '/';
    const repoPath = pruneDir + (headSha ? headSha.slice(0, 12) : String(Date.now())) + ext;
    if (dryRun) {
      imageUrl = imageUrlFor('DRYRUNCOMMITSHA', repoPath, isPrivate);
      console.log('[dry run] would commit ' + image + ' to ' + assetsBranch + ':' + repoPath);
    } else {
      try {
        const commitSha = await uploadImage(
          request,
          image,
          repoPath,
          pruneDir,
          'Scorecard for #' + pr.number + ' at ' + (headSha ? headSha.slice(0, 7) : 'unknown')
        );
        imageUrl = imageUrlFor(commitSha, repoPath, isPrivate);
      } catch (err) {
        const reason = err && err.message ? err.message : String(err);
        warning('Could not store the Scorecard image on ' + assetsBranch + ': ' + reason +
          '. The comment shows the figures as a table instead. The workflow needs `contents: write`.');
        notes.push('The Scorecard image could not be stored on the `' + assetsBranch + '` branch, so this comment shows the figures as a table. The job log has the reason.');
      }
    }
  }

  const state = {
    project,
    summary,
    imageUrl,
    runUrl,
    headSha,
    exitCode: Number(env('DR_EXIT_CODE', '0')),
    failOn: env('DR_FAIL_ON', ''),
    scanLog: readText(env('DR_SCAN_LOG', '')),
    compareText: readText(env('DR_COMPARE_LOG', '')),
    baseline: env('DR_BASELINE', ''),
    artifactName: env('DR_ARTIFACT_NAME', ''),
    notes,
  };

  let body = buildBody(state);
  if (body.length > GITHUB_COMMENT_LIMIT) {
    body = buildBody(Object.assign({}, state, { compareText: '', scanLog: '' })) +
      '\n> Some detail was left out to fit GitHub\'s comment size limit. The job log has all of it.\n';
  }

  let commentUrl = '';
  if (canPublish) {
    if (dryRun) {
      console.log('[dry run] comment body for PR #' + pr.number + ':\n');
      console.log(body);
    } else {
      try {
        commentUrl = await upsertComment(request, pr.number, body);
        console.log('Scorecard comment: ' + commentUrl);
      } catch (err) {
        warning('Could not post the PR comment: ' + (err && err.message ? err.message : err) +
          '. The workflow needs `pull-requests: write`.');
      }
    }
  } else if (dryRun) {
    console.log('[dry run] no PR comment (not a pull request, comment disabled, or read-only token)');
  }

  const summaryFile = env('GITHUB_STEP_SUMMARY', '');
  const summaryBody = buildBody(Object.assign({}, state, { forSummary: true }));
  if (summaryFile) {
    fs.appendFileSync(summaryFile, summaryBody + '\n');
  } else if (dryRun) {
    console.log('[dry run] job summary:\n');
    console.log(summaryBody);
  }

  setOutput('image-url', imageUrl);
  setOutput('comment-url', commentUrl);
}

main().catch((err) => {
  warning('Publishing the scorecard failed: ' + (err && err.stack ? err.stack : err));
});
